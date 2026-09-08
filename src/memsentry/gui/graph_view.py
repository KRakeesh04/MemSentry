"""Relationship Graph View for MemSentry.

Visualizes process hierarchy, attack chains, C2 network channels, file access,
and memory injections as an interactive graph topology with node inspection.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.theme import create_badge_label


@dataclass
class GraphNodeData:
    """Data structure for graph nodes."""

    id: str
    title: str
    subtitle: str
    category: str  # "process", "network", "file", "user", "dll"
    color: str  # Border & accent color
    bg_color: str  # Card background color
    rel_x: float  # Normalized X coordinate (0.0 - 1.0)
    rel_y: float  # Normalized Y coordinate (0.0 - 1.0)
    is_selected: bool = False
    title_color: str = "#F8FAFC"
    badges: list[tuple[str, str]] = field(default_factory=list)  # (text, badge_type)
    relationships: list[tuple[str, str, str]] = field(default_factory=list)  # (dir_arrow, node_name, rel_label)


GRAPH_NODES: dict[str, GraphNodeData] = {
    "jdoe": GraphNodeData(
        id="jdoe",
        title="CORP\\jdoe",
        subtitle="Domain User",
        category="user",
        color="#10B981",
        bg_color="#062C1E",
        rel_x=0.14,
        rel_y=0.50,
        title_color="#10B981",
        badges=[("User", "user"), ("INFO", "info")],
        relationships=[("→", "WINWORD.EXE", "executed")],
    ),
    "winword": GraphNodeData(
        id="winword",
        title="WINWORD.EXE",
        subtitle="PID 8192",
        category="process",
        color="#3B82F6",
        bg_color="#172554",
        rel_x=0.27,
        rel_y=0.50,
        title_color="#60A5FA",
        badges=[("Process", "blue"), ("SUSPICIOUS", "high")],
        relationships=[
            ("←", "CORP\\jdoe", "executed by"),
            ("→", "powershell.exe", "spawned"),
            ("→", "cmd.exe", "spawned"),
        ],
    ),
    "powershell": GraphNodeData(
        id="powershell",
        title="powershell.exe",
        subtitle="PID 9248",
        category="process",
        color="#EF4444",
        bg_color="#450A0A",
        rel_x=0.43,
        rel_y=0.28,
        is_selected=True,
        title_color="#EF4444",
        badges=[("Process", "blue"), ("CRITICAL", "critical")],
        relationships=[
            ("←", "WINWORD.EXE", "spawned"),
            ("→", "185.220.101.47", "C2 beacon"),
            ("→", "cmd.exe", "spawned"),
        ],
    ),
    "c2_tor": GraphNodeData(
        id="c2_tor",
        title="185.220.101.47",
        subtitle=":443 · TOR C2",
        category="network",
        color="#EF4444",
        bg_color="#450A0A",
        rel_x=0.58,
        rel_y=0.18,
        title_color="#EF4444",
        badges=[("Network", "network"), ("CRITICAL", "critical")],
        relationships=[("←", "powershell.exe", "C2 beacon")],
    ),
    "cmd": GraphNodeData(
        id="cmd",
        title="cmd.exe",
        subtitle="PID 9712",
        category="process",
        color="#F59E0B",
        bg_color="#451A03",
        rel_x=0.43,
        rel_y=0.62,
        title_color="#F59E0B",
        badges=[("Process", "blue"), ("SUSPICIOUS", "high")],
        relationships=[
            ("←", "WINWORD.EXE", "spawned"),
            ("←", "powershell.exe", "spawned"),
            ("→", "rundll32.exe", "exec"),
        ],
    ),
    "rundll": GraphNodeData(
        id="rundll",
        title="rundll32.exe",
        subtitle="PID 10284",
        category="process",
        color="#F59E0B",
        bg_color="#451A03",
        rel_x=0.57,
        rel_y=0.62,
        title_color="#F59E0B",
        badges=[("Process", "blue"), ("HIGH", "high")],
        relationships=[
            ("←", "cmd.exe", "exec"),
            ("→", "kb1281.dat", "loaded"),
            ("→", "svchost.exe", "injected"),
        ],
    ),
    "kb1281": GraphNodeData(
        id="kb1281",
        title="kb1281.dat",
        subtitle="C:\\...\\Temp\\",
        category="file",
        color="#F59E0B",
        bg_color="#451A03",
        rel_x=0.65,
        rel_y=0.45,
        title_color="#F59E0B",
        badges=[("File", "file"), ("SUSPICIOUS", "high")],
        relationships=[("←", "rundll32.exe", "loaded")],
    ),
    "svchost": GraphNodeData(
        id="svchost",
        title="svchost.exe",
        subtitle="PID 10891 · INJECTED",
        category="process",
        color="#EF4444",
        bg_color="#450A0A",
        rel_x=0.70,
        rel_y=0.76,
        title_color="#EF4444",
        badges=[("Process", "blue"), ("INJECTED", "critical")],
        relationships=[
            ("←", "rundll32.exe", "injected"),
            ("→", "45.33.32.156", "shell"),
        ],
    ),
    "revshell": GraphNodeData(
        id="revshell",
        title="45.33.32.156",
        subtitle=":4444 · Rev Shell",
        category="network",
        color="#EF4444",
        bg_color="#450A0A",
        rel_x=0.82,
        rel_y=0.84,
        title_color="#EF4444",
        badges=[("Network", "network"), ("CRITICAL", "critical")],
        relationships=[("←", "svchost.exe", "shell")],
    ),
}

GRAPH_EDGES: list[dict[str, str]] = [
    {"src": "winword", "dst": "powershell", "label": "spawned", "style": "solid", "color": "#EF4444"},
    {"src": "winword", "dst": "cmd", "label": "spawned", "style": "dotted", "color": "#64748B"},
    {"src": "powershell", "dst": "c2_tor", "label": "C2 beacon", "style": "solid", "color": "#EF4444"},
    {"src": "powershell", "dst": "cmd", "label": "spawned", "style": "solid", "color": "#EF4444"},
    {"src": "cmd", "dst": "rundll", "label": "exec", "style": "solid", "color": "#F59E0B"},
    {"src": "rundll", "dst": "kb1281", "label": "loaded", "style": "solid", "color": "#F59E0B"},
    {"src": "rundll", "dst": "svchost", "label": "injected", "style": "solid", "color": "#EF4444"},
    {"src": "svchost", "dst": "revshell", "label": "shell", "style": "solid", "color": "#EF4444"},
]


class GraphCanvasWidget(QWidget):
    """Custom painted widget rendering graph topology, grid, edges, and node cards."""

    node_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMouseTracking(True)
        self.node_rects: dict[str, QRectF] = {}

    def paintEvent(self, event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # 1. Background Fill
        painter.fillRect(self.rect(), QColor("#0B0F19"))

        # 2. Dark Grid Pattern
        grid_pen = QPen(QColor(21, 30, 50, 160), 1, Qt.PenStyle.SolidLine)
        painter.setPen(grid_pen)
        grid_size = 36
        x = 0
        while x < self.width():
            painter.drawLine(x, 0, x, self.height())
            x += grid_size
        y = 0
        while y < self.height():
            painter.drawLine(0, y, self.width(), y)
            y += grid_size

        # 3. Canvas Header Title
        title_font = QFont("Inter", 10, QFont.Weight.Medium)
        painter.setFont(title_font)
        painter.setPen(QPen(QColor("#64748B")))
        painter.drawText(24, 32, "CORP-2024-0187 · Attack Chain Visualization")

        # 4. Calculate Node Card Rectangles
        card_w = 148.0
        card_h = 52.0
        self.node_rects.clear()

        for nid, node in GRAPH_NODES.items():
            cx = node.rel_x * w
            cy = node.rel_y * h
            rect = QRectF(cx - card_w / 2.0, cy - card_h / 2.0, card_w, card_h)
            self.node_rects[nid] = rect

        # 5. Draw Directed Edges & Edge Labels
        for edge in GRAPH_EDGES:
            src_id = edge["src"]
            dst_id = edge["dst"]
            if src_id not in self.node_rects or dst_id not in self.node_rects:
                continue

            r_src = self.node_rects[src_id]
            r_dst = self.node_rects[dst_id]

            p1 = r_src.center()
            p2 = r_dst.center()

            edge_color = QColor(edge["color"])
            pen_style = Qt.PenStyle.SolidLine if edge["style"] == "solid" else Qt.PenStyle.DashLine
            pen = QPen(edge_color, 1.6, pen_style)
            painter.setPen(pen)
            painter.drawLine(p1, p2)

            # Draw Arrowhead
            angle = math.atan2(p2.y() - p1.y(), p2.x() - p1.x())
            arrow_size = 7.0
            # Offset arrowhead to edge of destination box
            arrow_p = QPointF(
                p2.x() - (card_w / 2.2) * math.cos(angle),
                p2.y() - (card_h / 2.2) * math.sin(angle),
            )
            sin_a = math.sin(angle)
            cos_a = math.cos(angle)
            p_left = QPointF(
                arrow_p.x() - arrow_size * cos_a + arrow_size * sin_a * 0.5,
                arrow_p.y() - arrow_size * sin_a - arrow_size * cos_a * 0.5,
            )
            p_right = QPointF(
                arrow_p.x() - arrow_size * cos_a - arrow_size * sin_a * 0.5,
                arrow_p.y() - arrow_size * sin_a + arrow_size * cos_a * 0.5,
            )
            arrow_path = QPainterPath()
            arrow_path.moveTo(arrow_p)
            arrow_path.lineTo(p_left)
            arrow_path.lineTo(p_right)
            arrow_path.closeSubpath()
            painter.fillPath(arrow_path, edge_color)

            # Draw Edge Text Label Box at Midpoint
            mid_x = (p1.x() + p2.x()) / 2.0
            mid_y = (p1.y() + p2.y()) / 2.0

            label_text = edge["label"]
            font_label = QFont("Inter", 8, QFont.Weight.Medium)
            painter.setFont(font_label)

            lbl_w = 64.0
            lbl_h = 16.0
            lbl_rect = QRectF(mid_x - lbl_w / 2.0, mid_y - lbl_h / 2.0, lbl_w, lbl_h)

            painter.setPen(QPen(QColor("#1E293B"), 1))
            painter.setBrush(QColor("#0F172A"))
            painter.drawRoundedRect(lbl_rect, 3, 3)

            painter.setPen(QPen(edge_color))
            painter.drawText(lbl_rect, Qt.AlignmentFlag.AlignCenter, label_text)

        # 6. Draw Node Cards
        for nid, node in GRAPH_NODES.items():
            rect = self.node_rects[nid]

            # Selection Glow Box
            if node.is_selected:
                glow_rect = rect.adjusted(-4, -4, 4, 4)
                painter.setPen(QPen(QColor("#38BDF8"), 2.2))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawRoundedRect(glow_rect, 8, 8)

            # Main Card Box
            painter.setPen(QPen(QColor(node.color), 1.5))
            painter.setBrush(QColor(node.bg_color))
            painter.drawRoundedRect(rect, 6, 6)

            # Node Title Text
            painter.setFont(QFont("Inter", 9, QFont.Weight.Bold))
            painter.setPen(QPen(QColor(node.title_color)))
            title_rect = QRectF(rect.x() + 10, rect.y() + 6, rect.width() - 20, 16)
            painter.drawText(title_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, node.title)

            # Subtitle Text
            painter.setFont(QFont("Inter", 8))
            painter.setPen(QPen(QColor("#94A3B8")))
            sub_rect = QRectF(rect.x() + 10, rect.y() + 22, rect.width() - 20, 14)
            painter.drawText(sub_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, node.subtitle)

            # Category Tag Badge (Bottom Pill inside card)
            tag_rect = QRectF(rect.x() + 10, rect.y() + 35, 48, 12)
            tag_bg_colors = {
                "process": QColor("#1E3A8A"),
                "network": QColor("#450A0A"),
                "file": QColor("#451A03"),
                "user": QColor("#064E3B"),
                "dll": QColor("#3B0764"),
            }
            tag_text_colors = {
                "process": QColor("#60A5FA"),
                "network": QColor("#F87171"),
                "file": QColor("#FBBF24"),
                "user": QColor("#34D399"),
                "dll": QColor("#C084FC"),
            }
            bg_c = tag_bg_colors.get(node.category, QColor("#1E293B"))
            tx_c = tag_text_colors.get(node.category, QColor("#94A3B8"))

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(bg_c)
            painter.drawRoundedRect(tag_rect, 3, 3)

            painter.setFont(QFont("Inter", 7, QFont.Weight.Bold))
            painter.setPen(QPen(tx_c))
            painter.drawText(tag_rect, Qt.AlignmentFlag.AlignCenter, node.category.lower())

    def mousePressEvent(self, event: object) -> None:
        pos = getattr(event, "position", lambda: getattr(event, "pos", lambda: QPointF())())()
        x = pos.x()
        y = pos.y()

        for nid, rect in self.node_rects.items():
            if rect.contains(x, y):
                for node in GRAPH_NODES.values():
                    node.is_selected = (node.id == nid)
                self.update()
                self.node_selected.emit(nid)
                break


class RelationshipGraphView(QWidget):
    """Relationship Graph view matching the MemSentry Figma Attack Chain design."""

    back_to_investigation_requested = Signal()
    view_in_process_tree_requested = Signal()
    show_in_timeline_requested = Signal()
    check_findings_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("RelationshipGraphView")
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(12)

        # 1. Top Sub-Header Bar
        sub_header = QHBoxLayout()
        sub_header.setSpacing(12)

        title_lbl = QLabel("RELATIONSHIP GRAPH")
        title_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #CBD5E1; letter-spacing: 0.5px;")
        sub_header.addWidget(title_lbl)

        # Category Filter Chips
        chips_layout = QHBoxLayout()
        chips_layout.setSpacing(6)

        categories = [
            ("Process", True),
            ("Network", False),
            ("File", False),
            ("User", False),
            ("Dll", False),
        ]
        for name, active in categories:
            btn = QPushButton(name)
            if active:
                btn.setStyleSheet(
                    "background: #1E293B; border: 1px solid #3B82F6; color: #38BDF8; "
                    "font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 4px;"
                )
            else:
                btn.setStyleSheet(
                    "background: #0F172A; border: 1px solid #1E293B; color: #94A3B8; "
                    "font-size: 12px; font-weight: 500; padding: 4px 12px; border-radius: 4px;"
                )
            chips_layout.addWidget(btn)

        sub_header.addLayout(chips_layout)
        sub_header.addStretch()

        # Top Right Navigation Button
        investigation_btn = QPushButton("← Investigation")
        investigation_btn.setStyleSheet(
            "background: #1E293B; border: 1px solid #334155; color: #E2E8F0; "
            "font-size: 12px; font-weight: 600; padding: 5px 14px; border-radius: 4px;"
        )
        investigation_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        investigation_btn.clicked.connect(self.back_to_investigation_requested.emit)
        sub_header.addWidget(investigation_btn)

        main_layout.addLayout(sub_header)

        # 2. Main Center Body (Canvas Container + Right Node Inspector)
        body_layout = QHBoxLayout()
        body_layout.setSpacing(12)

        # Left Canvas Container
        canvas_container = QFrame()
        canvas_container.setStyleSheet("background: #080C14; border: 1px solid #1E293B; border-radius: 6px;")
        canvas_box = QVBoxLayout(canvas_container)
        canvas_box.setContentsMargins(0, 0, 0, 0)
        canvas_box.setSpacing(0)

        # Interactive Painted Canvas Widget
        self.canvas = GraphCanvasWidget()
        self.canvas.node_selected.connect(self._on_node_selected)
        canvas_box.addWidget(self.canvas, stretch=1)

        # Floating Bottom Alert Banner Overlay
        alert_banner = QFrame()
        alert_banner.setStyleSheet(
            "background: #0F172A; border: 1px solid #334155; border-radius: 6px; margin: 8px 120px;"
        )
        alert_box = QHBoxLayout(alert_banner)
        alert_box.setContentsMargins(16, 8, 16, 8)

        warning_icon = QLabel("⚠️")
        warning_icon.setStyleSheet("font-size: 14px;")
        alert_box.addWidget(warning_icon)

        alert_msg = QLabel("Live preview failed ID: srid_8HA9Z7BYX247RY565JHN507R")
        alert_msg.setStyleSheet("color: #E2E8F0; font-size: 12px; font-weight: 600; font-family: monospace;")
        alert_box.addWidget(alert_msg)

        alert_box.addStretch()

        retry_btn = QPushButton("Retry")
        retry_btn.setStyleSheet(
            "background: #1E293B; border: 1px solid #475569; color: #F8FAFC; "
            "font-size: 11px; font-weight: 600; padding: 4px 14px; border-radius: 4px;"
        )
        alert_box.addWidget(retry_btn)

        canvas_box.addWidget(alert_banner)

        # Bottom Legend Bar
        legend_frame = QFrame()
        legend_frame.setStyleSheet("background: #0B0F19; border-top: 1px solid #1E293B;")
        legend_box = QHBoxLayout(legend_frame)
        legend_box.setContentsMargins(16, 8, 16, 8)
        legend_box.setSpacing(16)

        legend_title = QLabel("LEGEND")
        legend_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")
        legend_box.addWidget(legend_title)

        legend_items = [
            ("● Process", "#3B82F6"),
            ("● Network", "#EF4444"),
            ("● File", "#F59E0B"),
            ("● User", "#10B981"),
            ("● Dll", "#8B5CF6"),
            ("● Registry", "#06B6D4"),
        ]
        for item_name, color_hex in legend_items:
            lbl = QLabel(item_name)
            lbl.setStyleSheet(f"color: {color_hex}; font-size: 11px; font-weight: 600;")
            legend_box.addWidget(lbl)

        edge_susp = QLabel("— Suspicious edge")
        edge_susp.setStyleSheet("color: #EF4444; font-size: 11px; font-weight: 600;")
        legend_box.addWidget(edge_susp)

        edge_norm = QLabel("------ Normal edge")
        edge_norm.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 500;")
        legend_box.addWidget(edge_norm)

        legend_box.addStretch()
        canvas_box.addWidget(legend_frame)

        body_layout.addWidget(canvas_container, stretch=3)

        # Right Node Inspector Panel
        inspector_panel = QFrame()
        inspector_panel.setFixedWidth(320)
        inspector_panel.setStyleSheet(
            "background: #0D1322; border: 1px solid #1E293B; border-radius: 6px;"
        )
        inspector_box = QVBoxLayout(inspector_panel)
        inspector_box.setContentsMargins(16, 16, 16, 16)
        inspector_box.setSpacing(14)

        insp_header = QLabel("NODE INSPECTOR")
        insp_header.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")
        inspector_box.addWidget(insp_header)

        # Selected Node Title & PID
        self.node_title_lbl = QLabel("powershell.exe")
        self.node_title_lbl.setStyleSheet("font-size: 18px; font-weight: 700; color: #EF4444;")
        inspector_box.addWidget(self.node_title_lbl)

        self.node_pid_lbl = QLabel("PID 9248")
        self.node_pid_lbl.setStyleSheet("font-size: 12px; color: #94A3B8;")
        inspector_box.addWidget(self.node_pid_lbl)

        # Badges Row
        self.badges_layout = QHBoxLayout()
        self.badges_layout.setSpacing(8)
        self.badges_layout.addStretch()
        inspector_box.addLayout(self.badges_layout)

        # Relationships Section
        rel_header = QLabel("Relationships (3)")
        rel_header.setStyleSheet("font-size: 12px; font-weight: 700; color: #CBD5E1; margin-top: 6px;")
        self.rel_header_lbl = rel_header
        inspector_box.addWidget(rel_header)

        self.relationships_box = QVBoxLayout()
        self.relationships_box.setSpacing(8)
        inspector_box.addLayout(self.relationships_box)

        inspector_box.addStretch()

        # Actions Section
        actions_header = QLabel("Actions")
        actions_header.setStyleSheet("font-size: 12px; font-weight: 700; color: #CBD5E1;")
        inspector_box.addWidget(actions_header)

        actions_box = QVBoxLayout()
        actions_box.setSpacing(8)

        btn_tree = QPushButton("▶  View in Process Tree")
        btn_tree.setStyleSheet(
            "background: #172554; border: 1px solid #1D4ED8; color: #60A5FA; "
            "font-size: 12px; font-weight: 600; padding: 8px; border-radius: 4px; text-align: left;"
        )
        btn_tree.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_tree.clicked.connect(self._on_view_in_process_tree)
        actions_box.addWidget(btn_tree)

        btn_timeline = QPushButton("▶  Show in Timeline")
        btn_timeline.setStyleSheet(
            "background: #172554; border: 1px solid #1D4ED8; color: #60A5FA; "
            "font-size: 12px; font-weight: 600; padding: 8px; border-radius: 4px; text-align: left;"
        )
        btn_timeline.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_timeline.clicked.connect(self.show_in_timeline_requested.emit)
        actions_box.addWidget(btn_timeline)

        btn_findings = QPushButton("▶  Check Findings")
        btn_findings.setStyleSheet(
            "background: #172554; border: 1px solid #1D4ED8; color: #60A5FA; "
            "font-size: 12px; font-weight: 600; padding: 8px; border-radius: 4px; text-align: left;"
        )
        btn_findings.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_findings.clicked.connect(self.check_findings_requested.emit)
        actions_box.addWidget(btn_findings)

        inspector_box.addLayout(actions_box)

        body_layout.addWidget(inspector_panel, stretch=1)
        main_layout.addLayout(body_layout, stretch=1)

        # Initial populate for powershell.exe
        self._on_node_selected("powershell")

    def _on_node_selected(self, node_id: str) -> None:
        node = GRAPH_NODES.get(node_id)
        if not node:
            return

        self.node_title_lbl.setText(node.title)
        self.node_title_lbl.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {node.title_color};")
        self.node_pid_lbl.setText(node.subtitle)

        # Rebuild Badges
        while self.badges_layout.count():
            child = self.badges_layout.takeAt(0)
            if child:
                w = child.widget()
                if w is not None:
                    w.deleteLater()

        for b_text, b_type in node.badges:
            badge = create_badge_label(b_text, b_type)
            self.badges_layout.addWidget(badge)
        self.badges_layout.addStretch()

        # Rebuild Relationships
        while self.relationships_box.count():
            child = self.relationships_box.takeAt(0)
            if child:
                w = child.widget()
                if w is not None:
                    w.deleteLater()

        self.rel_header_lbl.setText(f"Relationships ({len(node.relationships)})")

        for dir_arrow, target_name, rel_lbl in node.relationships:
            card = QFrame()
            card.setStyleSheet("background: #0B0F19; border: 1px solid #1E293B; border-radius: 4px;")
            card_box = QHBoxLayout(card)
            card_box.setContentsMargins(10, 8, 10, 8)

            arr_lbl = QLabel(dir_arrow)
            arr_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #64748B;")
            card_box.addWidget(arr_lbl)

            info_box = QVBoxLayout()
            info_box.setSpacing(2)

            name_lbl = QLabel(target_name)
            name_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #F8FAFC;")
            sub_lbl = QLabel(rel_lbl)
            sub_lbl.setStyleSheet("font-size: 10px; color: #94A3B8;")

            info_box.addWidget(name_lbl)
            info_box.addWidget(sub_lbl)
            card_box.addLayout(info_box)
            card_box.addStretch()

            self.relationships_box.addWidget(card)

    def _on_view_in_process_tree(self) -> None:
        self.view_in_process_tree_requested.emit()
        self.back_to_investigation_requested.emit()
