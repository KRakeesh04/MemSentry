"""Theme-aware native investigation cards and a zoomable grid canvas."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QRect, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPalette, QPen, QWheelEvent
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSceneMouseEvent,
    QGraphicsView,
    QStyleOptionGraphicsItem,
    QWidget,
)

if TYPE_CHECKING:
    from memsentry.gui.pages.investigation_graph import InvestigationGraphPage


def graph_colors(palette: QPalette) -> dict[str, QColor]:
    dark = palette.color(QPalette.ColorRole.Window).lightness() < 128
    values = (("#11151C", "#1B212B", "#E5E7EB", "#A5B0C0", "#303947", "#60A5FA")
              if dark else
              ("#F1F5F9", "#FFFFFF", "#172033", "#526174", "#DCE3EC", "#2563EB"))
    return dict(zip(("background", "surface", "text", "muted", "border", "accent"),
                    map(QColor, values), strict=True))


class GraphView(QGraphicsView):
    def __init__(self, scene: QGraphicsScene) -> None:
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setAccessibleName("Investigation graph: drag background to pan; scroll to zoom")
        self.setMinimumSize(320, 300)

    def zoom(self, factor: float) -> None:
        if 0.08 <= self.transform().m11() * factor <= 4:
            self.scale(factor, factor)

    def wheelEvent(self, event: QWheelEvent) -> None:
        self.zoom(1.2 if event.angleDelta().y() > 0 else 1 / 1.2)
        event.accept()

    def drawBackground(self, painter: QPainter, rect: QRectF | QRect) -> None:
        colors = graph_colors(self.palette())
        painter.fillRect(rect, colors["background"])
        grid = colors["border"]
        grid.setAlpha(90)
        painter.setPen(QPen(grid, 0))
        step = 32 if self.transform().m11() > .35 else 128
        for x in range(math.floor(rect.left() / step) * step, math.ceil(rect.right()), step):
            painter.drawLine(x, int(rect.top()), x, int(rect.bottom()))
        for y in range(math.floor(rect.top() / step) * step, math.ceil(rect.bottom()), step):
            painter.drawLine(int(rect.left()), y, int(rect.right()), y)


class NodeItem(QGraphicsRectItem):
    def __init__(self, key: str, page: InvestigationGraphPage) -> None:
        super().__init__(0, 0, 240, 96)
        self.key, self.page = key, page
        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
                      | QGraphicsItem.GraphicsItemFlag.ItemIsMovable
                      | QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setData(0, key)

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem,
              widget: QWidget | None = None) -> None:
        colors = graph_colors(self.page.palette())
        node = self.page.graph.nodes[self.key]
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(colors["surface"])
        painter.setPen(QPen(colors["accent"] if self.isSelected() else colors["border"],
                            2 if self.isSelected() else 1))
        painter.drawRoundedRect(self.rect(), 10, 10)
        painter.setPen(QPen(colors["accent"], 3))
        painter.drawLine(1, 16, 1, 80)
        painter.setPen(colors["text"])
        font = QFont(self.page.font())
        font.setBold(True)
        painter.setFont(font)
        title = painter.fontMetrics().elidedText(node.label, Qt.TextElideMode.ElideRight, 208)
        painter.drawText(QRectF(16, 12, 208, 25), title)
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(colors["muted"])
        detail = ("Manual · " + str(node.details.get("category", "hypothesis"))
                  if node.kind == "hypothesis" else
                  f"Finding · {node.details.get('severity', 'review')}" if node.kind == "finding"
                  else f"PID {node.details['pid']}" if node.details.get("pid") is not None
                  else "Captured artifact")
        painter.drawText(QRectF(16, 39, 208, 23), detail)
        painter.setPen(colors["accent"])
        painter.drawText(QRectF(16, 66, 208, 22), node.kind.replace("_", " ").upper())

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value: Any) -> Any:
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self.page.update_edges()
            if not self.page._rendering:
                self.page.capture_edit()
        return super().itemChange(change, value)

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        self.page._moving = True
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        super().mouseReleaseEvent(event)
        self.page._moving = False
        self.page.capture_edit()
