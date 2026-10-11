"""Interactive QGraphicsView and QGraphicsScene canvas for the forensic graph."""

from __future__ import annotations

import math
from typing import Any, Callable

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QPainter,
    QPainterPath,
    QPen,
    QWheelEvent,
)
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsScene,
    QGraphicsView,
    QWidget,
)

from memsentry.graph.models import GraphData, GraphEdge, GraphNode, NodeType

NODE_COLORS = {
    "evidence": {"bg": "#3B82F6", "border": "#1D4ED8", "text": "#FFFFFF"},      # Blue
    "process": {"bg": "#10B981", "border": "#047857", "text": "#FFFFFF"},       # Emerald/Green
    "network": {"bg": "#8B5CF6", "border": "#6D28D9", "text": "#FFFFFF"},       # Purple
    "finding": {"bg": "#EF4444", "border": "#B91C1C", "text": "#FFFFFF"},       # Red
}

NODE_SHAPES = {
    "evidence": "octagon",
    "process": "rounded_rect",
    "network": "diamond",
    "finding": "hexagon",
}


class NodeGraphicsItem(QGraphicsItem):
    """Visual representation of a single GraphNode."""

    def __init__(
        self,
        node: GraphNode,
        on_selected: Callable[[GraphNode], None],
    ) -> None:
        super().__init__()
        self.node = node
        self.on_selected = on_selected
        self.width = 130.0
        self.height = 46.0
        self.is_hovered = False
        self.is_active = False
        self.is_dimmed = False

        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setPos(node.x, node.y)
        self.setZValue(10)

    def boundingRect(self) -> QRectF:
        pad = 4.0
        return QRectF(-self.width / 2 - pad, -self.height / 2 - pad, self.width + pad * 2, self.height + pad * 2)

    def shape(self) -> QPainterPath:
        path = QPainterPath()
        path.addRoundedRect(-self.width / 2, -self.height / 2, self.width, self.height, 8, 8)
        return path

    def paint(self, painter: QPainter, option: Any, widget: QWidget | None = None) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        node_color = NODE_COLORS.get(self.node.node_type, NODE_COLORS["process"])
        bg_color = QColor(node_color["bg"])
        border_color = QColor(node_color["border"])

        if self.is_dimmed:
            bg_color.setAlpha(70)
            border_color.setAlpha(80)
        elif self.is_active or self.isSelected():
            border_color = QColor("#FACC15")  # Bright Yellow highlight
            painter.setPen(QPen(border_color, 3.0))
        elif self.is_hovered:
            border_color = QColor("#FFFFFF")
            painter.setPen(QPen(border_color, 2.0))
        else:
            painter.setPen(QPen(border_color, 1.5))

        painter.setBrush(QBrush(bg_color))

        rect = QRectF(-self.width / 2, -self.height / 2, self.width, self.height)
        node_shape = NODE_SHAPES.get(self.node.node_type, "rounded_rect")

        if node_shape == "rounded_rect":
            painter.drawRoundedRect(rect, 8, 8)
        elif node_shape == "octagon":
            path = QPainterPath()
            w, h = self.width / 2, self.height / 2
            cut = 10.0
            path.moveTo(-w + cut, -h)
            path.lineTo(w - cut, -h)
            path.lineTo(w, -h + cut)
            path.lineTo(w, h - cut)
            path.lineTo(w - cut, h)
            path.lineTo(-w + cut, h)
            path.lineTo(-w, h - cut)
            path.lineTo(-w, -h + cut)
            path.closeSubpath()
            painter.drawPath(path)
        elif node_shape == "diamond":
            path = QPainterPath()
            w, h = self.width / 2, self.height / 2
            path.moveTo(0, -h)
            path.lineTo(w, 0)
            path.lineTo(0, h)
            path.lineTo(-w, 0)
            path.closeSubpath()
            painter.drawPath(path)
        elif node_shape == "hexagon":
            path = QPainterPath()
            w, h = self.width / 2, self.height / 2
            cut = 14.0
            path.moveTo(-w + cut, -h)
            path.lineTo(w - cut, -h)
            path.lineTo(w, 0)
            path.lineTo(w - cut, h)
            path.lineTo(-w + cut, h)
            path.lineTo(-w, 0)
            path.closeSubpath()
            painter.drawPath(path)

        # Label Text
        text_color = QColor(node_color["text"])
        if self.is_dimmed:
            text_color.setAlpha(80)

        painter.setPen(QPen(text_color))
        font = QFont("Segoe UI", 9)
        font.setBold(True)
        painter.setFont(font)

        label_rect = QRectF(-self.width / 2 + 6, -self.height / 2 + 4, self.width - 12, 18)
        elided_label = painter.fontMetrics().elidedText(
            self.node.label, Qt.TextElideMode.ElideRight, int(label_rect.width())
        )
        painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, elided_label)

        # Subtitle Text
        sub_font = QFont("Segoe UI", 7)
        painter.setFont(sub_font)
        subtitle_color = QColor(255, 255, 255, 210)

        if self.is_dimmed:
            subtitle_color.setAlpha(70)

        painter.setPen(QPen(subtitle_color))
        sub_rect = QRectF(-self.width / 2 + 6, -self.height / 2 + 22, self.width - 12, 16)
        elided_sub = painter.fontMetrics().elidedText(
            self.node.subtitle, Qt.TextElideMode.ElideRight, int(sub_rect.width())
        )
        painter.drawText(sub_rect, Qt.AlignmentFlag.AlignCenter, elided_sub)

    def hoverEnterEvent(self, event: Any) -> None:
        self.is_hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event: Any) -> None:
        self.is_hovered = False
        self.update()
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event: Any) -> None:
        self.on_selected(self.node)
        super().mousePressEvent(event)


class EdgeGraphicsItem(QGraphicsLineItem):
    """Visual directed edge between two nodes with an arrow."""

    def __init__(self, edge: GraphEdge, source_item: NodeGraphicsItem, target_item: NodeGraphicsItem) -> None:
        super().__init__()
        self.edge = edge
        self.source_item = source_item
        self.target_item = target_item
        self.is_dimmed = False
        self.is_highlighted = False
        self.setZValue(1)
        self.update_position()

    def update_position(self) -> None:
        p1 = self.source_item.pos()
        p2 = self.target_item.pos()
        self.setLine(p1.x(), p1.y(), p2.x(), p2.y())

    def paint(self, painter: QPainter, option: Any, widget: QWidget | None = None) -> None:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        p1 = self.source_item.pos()
        p2 = self.target_item.pos()

        dx = p2.x() - p1.x()
        dy = p2.y() - p1.y()
        dist = math.hypot(dx, dy)
        if dist < 1.0:
            return

        # Shorten line slightly so arrow lands at border of target node
        ux = dx / dist
        uy = dy / dist
        target_radius = 28.0
        arrow_tip_x = p2.x() - ux * target_radius
        arrow_tip_y = p2.y() - uy * target_radius

        if self.is_highlighted:
            edge_color = QColor("#60A5FA")
            edge_width = 2.4
        elif self.is_dimmed:
            edge_color = QColor(140, 155, 175, 35)
            edge_width = 1.0
        else:
            edge_color = QColor(140, 155, 175, 130)
            edge_width = 1.4

        painter.setPen(
            QPen(edge_color, edge_width, Qt.PenStyle.SolidLine)
        )
        painter.drawLine(QPointF(p1.x(), p1.y()), QPointF(arrow_tip_x, arrow_tip_y))

        # Arrow head
        arrow_size = 7.0
        angle = math.atan2(dy, dx)
        p_arrow1 = QPointF(
            arrow_tip_x - arrow_size * math.cos(angle - math.pi / 6),
            arrow_tip_y - arrow_size * math.sin(angle - math.pi / 6),
        )
        p_arrow2 = QPointF(
            arrow_tip_x - arrow_size * math.cos(angle + math.pi / 6),
            arrow_tip_y - arrow_size * math.sin(angle + math.pi / 6),
        )
        arrow_path = QPainterPath()
        arrow_path.moveTo(QPointF(arrow_tip_x, arrow_tip_y))
        arrow_path.lineTo(p_arrow1)
        arrow_path.lineTo(p_arrow2)
        arrow_path.closeSubpath()

        painter.setBrush(QBrush(edge_color))
        painter.drawPath(arrow_path)


class GraphCanvas(QGraphicsView):
    """QGraphicsView for zooming, panning, and rendering the investigation graph."""

    node_selected = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.node_items: dict[str, NodeGraphicsItem] = {}
        self.edge_items: list[EdgeGraphicsItem] = []
        self._current_scale = 1.0

    def wheelEvent(self, event: QWheelEvent) -> None:
        """Zoom in/out with mouse scroll."""
        zoom_factor = 1.15
        if event.angleDelta().y() > 0:
            if self._current_scale < 4.0:
                self.scale(zoom_factor, zoom_factor)
                self._current_scale *= zoom_factor
        else:
            if self._current_scale > 0.25:
                self.scale(1.0 / zoom_factor, 1.0 / zoom_factor)
                self._current_scale /= zoom_factor

    def mousePressEvent(self, event) -> None:
        item = self.itemAt(event.pos())

        if item is None:
            for node_item in self.node_items.values():
                node_item.is_active = False
                node_item.is_dimmed = False
                node_item.setSelected(False)
                node_item.update()

            for edge_item in self.edge_items:
                edge_item.is_highlighted = False
                edge_item.is_dimmed = False
                edge_item.update()

        super().mousePressEvent(event)

    def zoom_in(self) -> None:
        zoom_factor = 1.15

        if self._current_scale < 4.0:
            self.scale(zoom_factor, zoom_factor)
            self._current_scale *= zoom_factor


    def zoom_out(self) -> None:
        zoom_factor = 1.15

        if self._current_scale > 0.25:
            self.scale(1.0 / zoom_factor, 1.0 / zoom_factor)
            self._current_scale /= zoom_factor


    def pan_left(self) -> None:
        bar = self.horizontalScrollBar()
        bar.setValue(bar.value() - 100)


    def pan_right(self) -> None:
        bar = self.horizontalScrollBar()
        bar.setValue(bar.value() + 100)


    def pan_up(self) -> None:
        bar = self.verticalScrollBar()
        bar.setValue(bar.value() - 100)


    def pan_down(self) -> None:
        bar = self.verticalScrollBar()
        bar.setValue(bar.value() + 100)

    def reset_view(self) -> None:
        """Fit all graph contents into the current view port."""
        self.resetTransform()
        self._current_scale = 1.0
        if not self.scene.items():
            return
        rect = self.scene.itemsBoundingRect()
        if not rect.isEmpty():
            self.fitInView(rect.adjusted(-50, -50, 50, 50), Qt.AspectRatioMode.KeepAspectRatio)
            # Update _current_scale estimate
            self._current_scale = self.transform().m11()

    def set_graph_data(
        self,
        graph_data: GraphData,
        visible_node_ids: set[str] | None = None,
    ) -> None:
        """Populate scene with nodes and edges using a hierarchical column layout."""
        self.scene.clear()
        self.node_items.clear()
        self.edge_items.clear()

        if not graph_data.nodes:
            return

        active_node_ids = set(graph_data.nodes.keys()) if visible_node_ids is None else visible_node_ids
        nodes_to_render = {nid: n for nid, n in graph_data.nodes.items() if nid in active_node_ids}

        # Organize nodes into semantic columns by type
        # Column 0: Evidence
        # Column 1: Processes
        # Column 2: Network & Findings
        col_evidence: list[GraphNode] = []
        col_process: list[GraphNode] = []
        col_network: list[GraphNode] = []
        col_finding: list[GraphNode] = []

        for node in nodes_to_render.values():
            if node.node_type == "evidence":
                col_evidence.append(node)
            elif node.node_type == "process":
                col_process.append(node)
            elif node.node_type == "network":
                col_network.append(node)
            elif node.node_type == "finding":
                col_finding.append(node)

        x_spacing = 260.0
        y_spacing = 75.0

        def layout_column(column_nodes: list[GraphNode], col_x: float, start_y_offset: float = 0.0) -> None:
            total_h = len(column_nodes) * y_spacing
            start_y = -total_h / 2.0 + start_y_offset
            for idx, node in enumerate(column_nodes):
                node.x = col_x
                node.y = start_y + idx * y_spacing

        layout_column(col_evidence, -x_spacing * 1.5)
        layout_column(col_process, -x_spacing * 0.5)
        layout_column(col_network, x_spacing * 0.5)
        layout_column(col_finding, x_spacing * 1.5)

        # Create Node items
        for node in nodes_to_render.values():
            item = NodeGraphicsItem(node, self._on_node_clicked)
            self.scene.addItem(item)
            self.node_items[node.id] = item

        # Create Edges
        for edge in graph_data.edges:
            if edge.source_id in self.node_items and edge.target_id in self.node_items:
                source_item = self.node_items[edge.source_id]
                target_item = self.node_items[edge.target_id]
                edge_item = EdgeGraphicsItem(edge, source_item, target_item)
                self.scene.addItem(edge_item)
                self.edge_items.append(edge_item)

        self.reset_view()

    def _on_node_clicked(self, node: GraphNode) -> None:
        connected_ids = {node.id}

        for edge_item in self.edge_items:
            edge = edge_item.edge

            connected = (
                edge.source_id == node.id
                or edge.target_id == node.id
            )

            edge_item.is_highlighted = connected
            edge_item.is_dimmed = not connected

            if connected:
                connected_ids.add(edge.source_id)
                connected_ids.add(edge.target_id)

            edge_item.update()

        for nid, item in self.node_items.items():
            item.is_active = nid == node.id
            item.is_dimmed = nid not in connected_ids
            item.update()

        self.node_selected.emit(node)
