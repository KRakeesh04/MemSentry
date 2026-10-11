"""Investigation Graph page for interactive forensic entity & relationship exploration."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from memsentry.graph.builder import GraphBuilder
from memsentry.graph.models import GraphData, GraphNode
from memsentry.gui.controls import ThemedComboBox
from memsentry.gui.pages.graph_canvas import GraphCanvas
from memsentry.models.case import Case

logger = logging.getLogger(__name__)


def _info_row(label: str, value: str) -> QWidget:
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 4, 0, 4)
    layout.setSpacing(2)
    lbl = QLabel(label.upper())
    lbl.setObjectName("muted")
    lbl.setStyleSheet("font-size: 10px; font-weight: bold;")
    val = QLabel(value)
    val.setWordWrap(True)
    val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    layout.addWidget(lbl)
    layout.addWidget(val)
    return container


class EntityDetailsPanel(QScrollArea):
    """Right-side inspector showing metadata and relationships of the selected node."""

    navigate_findings_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setObjectName("entityDetailsPanel")

        self.container = QWidget()
        self.layout = QVBoxLayout(self.container)
        self.layout.setContentsMargins(16, 16, 16, 16)
        self.layout.setSpacing(12)
        self.setWidget(self.container)

        self.show_empty()

    def show_empty(self) -> None:
        self._clear()
        title = QLabel("Selected Entity")
        title.setObjectName("sectionTitle")
        self.layout.addWidget(title)

        hint = QLabel("Click any node on the graph canvas to inspect its forensic properties and relationships.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        self.layout.addWidget(hint)
        self.layout.addStretch()

    def display_node(self, node: GraphNode, graph_data: GraphData) -> None:
        self._clear()

        # Header
        type_badge = QLabel(f"ENTITY TYPE: {node.node_type.upper()}")
        type_badge.setObjectName("muted")
        type_badge.setStyleSheet("font-size: 11px; font-weight: bold;")
        self.layout.addWidget(type_badge)

        name_lbl = QLabel(node.label)
        name_lbl.setObjectName("sectionTitle")
        name_lbl.setWordWrap(True)
        self.layout.addWidget(name_lbl)

        # Related connected nodes
        incoming = [e for e in graph_data.edges if e.target_id == node.id]
        outgoing = [e for e in graph_data.edges if e.source_id == node.id]

        if node.node_type == "process":
            pid = node.metadata.get("pid")
            ppid = node.metadata.get("ppid")
            self.layout.addWidget(_info_row("Process Name", str(node.metadata.get("process_name", node.label))))
            self.layout.addWidget(_info_row("PID", str(pid) if pid is not None else "N/A"))
            self.layout.addWidget(_info_row("Parent PID (PPID)", str(ppid) if ppid is not None else "N/A"))
            if node.metadata.get("evidence_name"):
                self.layout.addWidget(_info_row("Evidence Source", str(node.metadata["evidence_name"])))
            if node.metadata.get("created_at"):
                self.layout.addWidget(_info_row("Created At", str(node.metadata["created_at"])))
            if node.metadata.get("cmdline"):
                self.layout.addWidget(_info_row("Command Line", str(node.metadata["cmdline"])))

            # Connected endpoints & findings
            endpoints = [
                graph_data.nodes[e.target_id].label
                for e in outgoing
                if e.target_id in graph_data.nodes and graph_data.nodes[e.target_id].node_type == "network"
            ]
            if endpoints:
                self.layout.addWidget(_info_row("Network Endpoints", ", ".join(endpoints)))

            findings = [
                graph_data.nodes[e.source_id].label
                for e in incoming
                if e.source_id in graph_data.nodes and graph_data.nodes[e.source_id].node_type == "finding"
            ]
            if findings:
                self.layout.addWidget(_info_row("Related Findings", "; ".join(findings)))

        elif node.node_type == "network":
            meta = node.metadata
            endpoint = f"{meta.get('remote_address') or meta.get('local_address')}:{meta.get('remote_port') or meta.get('local_port')}"
            self.layout.addWidget(_info_row("Endpoint", endpoint))
            self.layout.addWidget(_info_row("Protocol", str(meta.get("protocol", "TCP"))))
            if meta.get("state"):
                self.layout.addWidget(_info_row("Connection State", str(meta["state"])))
            if meta.get("local_address"):
                self.layout.addWidget(_info_row("Local Address", f"{meta.get('local_address')}:{meta.get('local_port')}"))
            if meta.get("remote_address"):
                self.layout.addWidget(_info_row("Remote Address", f"{meta.get('remote_address')}:{meta.get('remote_port')}"))

            # Parent processes
            processes = [
                graph_data.nodes[e.source_id].label
                for e in incoming
                if e.source_id in graph_data.nodes and graph_data.nodes[e.source_id].node_type == "process"
            ]
            if processes:
                self.layout.addWidget(_info_row("Owner Process", ", ".join(processes)))

        elif node.node_type == "finding":
            meta = node.metadata
            self.layout.addWidget(_info_row("Finding Title", str(meta.get("title", node.label))))
            self.layout.addWidget(_info_row("Severity", str(meta.get("severity", "N/A")).upper()))
            self.layout.addWidget(_info_row("Rule ID", str(meta.get("rule_id", "N/A"))))
            conf = meta.get("confidence")
            self.layout.addWidget(_info_row("Confidence", f"{conf:.0%}" if isinstance(conf, float) else "Not recorded"))
            if meta.get("description"):
                self.layout.addWidget(_info_row("Description", str(meta["description"])))

            # Related processes
            flagged = [
                graph_data.nodes[e.target_id].label
                for e in outgoing
                if e.target_id in graph_data.nodes and graph_data.nodes[e.target_id].node_type == "process"
            ]
            if flagged:
                self.layout.addWidget(_info_row("Target Process", ", ".join(flagged)))

            view_btn = QPushButton("View in Findings Page")
            view_btn.clicked.connect(self.navigate_findings_requested.emit)
            self.layout.addWidget(view_btn)

        elif node.node_type == "evidence":
            meta = node.metadata
            self.layout.addWidget(_info_row("Evidence Name", str(meta.get("filename", node.label))))
            self.layout.addWidget(_info_row("Operating System", str(meta.get("operating_system", "N/A")).upper()))
            size = meta.get("size_bytes")
            size_mb = f"{size / (1024 * 1024):.2f} MB" if isinstance(size, (int, float)) else "N/A"
            self.layout.addWidget(_info_row("File Size", size_mb))
            self.layout.addWidget(_info_row("SHA-256 Hash", str(meta.get("sha256", "N/A"))))
            self.layout.addWidget(_info_row("Verification Status", str(meta.get("status", "verified")).capitalize()))

        self.layout.addStretch()

    def _clear(self) -> None:
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()


class InvestigationGraphPage(QWidget):
    """Main Investigation Graph page component."""

    findings_page_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.workspace_path = ""
        self.case: Case | None = None
        self.raw_graph_data = GraphData()

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(14)

        # ---------------- TOP TOOLBAR ----------------
        top_bar = QHBoxLayout()
        top_bar.setSpacing(12)

        self.title_lbl = QLabel("Investigation Graph")
        self.title_lbl.setObjectName("pageTitle")
        top_bar.addWidget(self.title_lbl)

        self.case_badge = QLabel("No case selected")
        self.case_badge.setObjectName("muted")
        top_bar.addWidget(self.case_badge)

        top_bar.addStretch()

        # Search field
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search PID, process, IP, rule...")
        self.search_input.setFixedWidth(220)
        self.search_input.textChanged.connect(self._apply_filters)
        top_bar.addWidget(self.search_input)

        # Entity type combo
        self.type_combo = ThemedComboBox()
        self.type_combo.addItems(["All Entity Types", "Processes", "Network", "Findings", "Evidence"])
        self.type_combo.currentIndexChanged.connect(self._apply_filters)
        top_bar.addWidget(self.type_combo)

        # Checkbox: Related to findings only
        self.findings_only_check = QCheckBox("Findings & connected only")
        self.findings_only_check.stateChanged.connect(self._apply_filters)
        top_bar.addWidget(self.findings_only_check)

        # Reset view button
        self.reset_btn = QPushButton("Reset View")
        self.reset_btn.clicked.connect(self._reset_view)
        top_bar.addWidget(self.reset_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        top_bar.addWidget(self.refresh_btn)

        main_layout.addLayout(top_bar)

        # ---------------- CENTER AREA (SPLITTER) ----------------
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)

        # Graph Canvas
        self.canvas = GraphCanvas(splitter)
        self.canvas.node_selected.connect(self._on_node_selected)
        splitter.addWidget(self.canvas)

        # Details Panel
        self.details_panel = EntityDetailsPanel(splitter)
        self.details_panel.navigate_findings_requested.connect(self.findings_page_requested.emit)
        self.details_panel.setMinimumWidth(260)
        self.details_panel.setMaximumWidth(360)
        splitter.addWidget(self.details_panel)

        splitter.setSizes([700, 300])
        main_layout.addWidget(splitter, 1)

        # ---------------- BOTTOM LEGEND & METRICS ----------------
        bottom_bar = QHBoxLayout()
        bottom_bar.setSpacing(16)

        legend_title = QLabel("Legend:")
        legend_title.setObjectName("muted")
        bottom_bar.addWidget(legend_title)

        def make_legend_item(text: str, color: str, symbol: str) -> QLabel:
            lbl = QLabel(f"{symbol} {text}")
            lbl.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 11px;")
            return lbl

        bottom_bar.addWidget(make_legend_item("Evidence", "#3B82F6", "⯁"))
        bottom_bar.addWidget(make_legend_item("Process", "#10B981", "■"))
        bottom_bar.addWidget(make_legend_item("Network", "#8B5CF6", "◆"))
        bottom_bar.addWidget(make_legend_item("Finding", "#EF4444", "⬢"))

        bottom_bar.addStretch()

        self.status_metrics = QLabel("No case selected")
        self.status_metrics.setObjectName("muted")
        bottom_bar.addWidget(self.status_metrics)

        main_layout.addLayout(bottom_bar)

    def open_case(self, workspace: str, case: Case) -> None:
        """Set active case and load graph data."""
        self.workspace_path = workspace
        self.case = case
        self.case_badge.setText(f"·  {case.case_number} ({case.name})")
        self.refresh()

    def refresh(self) -> None:
        """Reload graph data for active case."""
        if not self.case or not self.workspace_path:
            self.raw_graph_data = GraphData()
            self.canvas.set_graph_data(self.raw_graph_data)
            self.details_panel.show_empty()
            self.status_metrics.setText("No case selected")
            return

        try:
            self.raw_graph_data = GraphBuilder.build_for_case(self.workspace_path, self.case)
            self._apply_filters()
        except Exception as exc:
            logger.exception("Failed to build graph for case %s", self.case.id)
            self.status_metrics.setText(f"Error loading graph: {exc}")

    def _reset_view(self) -> None:
        self.canvas.reset_view()

    def _apply_filters(self) -> None:
        """Filter node visibility based on query text, entity type combo, and findings checkbox."""
        query = self.search_input.text().strip().lower()
        type_idx = self.type_combo.currentIndex()
        findings_only = self.findings_only_check.isChecked()

        # Type map
        # 0: All, 1: Process, 2: Network, 3: Finding, 4: Evidence
        type_filter = {
            1: "process",
            2: "network",
            3: "finding",
            4: "evidence",
        }.get(type_idx)

        # Finding-connected nodes set if requested
        finding_connected_ids: set[str] = set()
        if findings_only:
            finding_nodes = [nid for nid, n in self.raw_graph_data.nodes.items() if n.node_type == "finding"]
            for fnid in finding_nodes:
                finding_connected_ids.add(fnid)
                for edge in self.raw_graph_data.edges:
                    if edge.source_id == fnid:
                        finding_connected_ids.add(edge.target_id)
                    elif edge.target_id == fnid:
                        finding_connected_ids.add(edge.source_id)

        matching_node_ids: set[str] = set()
        for nid, node in self.raw_graph_data.nodes.items():
            if type_filter and node.node_type != type_filter:
                continue

            if findings_only and nid not in finding_connected_ids:
                continue

            if query:
                # Check label, subtitle, or metadata
                meta_str = " ".join(str(v) for v in node.metadata.values()).lower()
                if (
                    query not in node.label.lower()
                    and query not in node.subtitle.lower()
                    and query not in meta_str
                ):
                    continue

            matching_node_ids.add(nid)

        # Count active edges between matching nodes
        active_edges_count = sum(
            1
            for e in self.raw_graph_data.edges
            if e.source_id in matching_node_ids and e.target_id in matching_node_ids
        )

        self.canvas.set_graph_data(self.raw_graph_data, matching_node_ids)
        self.status_metrics.setText(
            f"{len(matching_node_ids)} Entities · {active_edges_count} Relationships"
        )

    def _on_node_selected(self, node: GraphNode) -> None:
        self.details_panel.display_node(node, self.raw_graph_data)


def create_page() -> QWidget:
    return InvestigationGraphPage()
