"""Interactive, run-scoped automated investigation graph."""

from __future__ import annotations

import json
import math
from uuid import UUID

from PySide6.QtCore import QLineF, QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QComboBox,
    QGraphicsItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.case_service import workspace_database
from memsentry.app.graph_service import InvestigationGraph, load_graph
from memsentry.models.case import Case
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository


class GraphView(QGraphicsView):
    def __init__(self, scene: QGraphicsScene) -> None:
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setAccessibleName("Investigation graph: drag background to pan; scroll to zoom")

    def zoom(self, factor: float) -> None:
        if 0.08 <= self.transform().m11() * factor <= 4:
            self.scale(factor, factor)

    def wheelEvent(self, event) -> None:
        self.zoom(1.2 if event.angleDelta().y() > 0 else 1 / 1.2)
        event.accept()


class NodeItem(QGraphicsRectItem):
    def __init__(self, key: str, page: InvestigationGraphPage) -> None:
        super().__init__(0, 0, 220, 64)
        self.key, self.page = key, page
        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable
                      | QGraphicsItem.GraphicsItemFlag.ItemIsMovable
                      | QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setData(0, key)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self.page.update_edges()
        return super().itemChange(change, value)


class InvestigationGraphPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.case = None
        self.workspace_path = ""
        self.graph = InvestigationGraph()
        self.visible: set[str] = set()
        self.node_items = {}
        self.edge_items = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        title = QLabel("Investigation Graph")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        self.run_choice = QComboBox()
        self.run_choice.setAccessibleName("Evidence and analysis run")
        toolbar = QHBoxLayout()
        toolbar.addWidget(self.run_choice, 1)
        refresh = QPushButton("Refresh runs")
        refresh.clicked.connect(self.refresh)
        toolbar.addWidget(refresh)
        layout.addLayout(toolbar)
        legend = QLabel("Original baseline · Solid → observed · Dashed → automated inference\n"
                        "Links show recorded associations, not a chronological action chain. "
                        "Missing data is not a clean result. Layout changes are view-only.")
        legend.setWordWrap(True)
        layout.addWidget(legend)
        controls = QHBoxLayout()
        for text, callback in (("Expand selected", self.expand_selected),
                               ("Fit view", self.fit_view), ("Fit selection", self.fit_selection),
                               ("Zoom in", lambda: self.view.zoom(1.2)),
                               ("Zoom out", lambda: self.view.zoom(1 / 1.2))):
            button = QPushButton(text)
            button.clicked.connect(callback)
            controls.addWidget(button)
        layout.addLayout(controls)
        splitter = QSplitter()
        picker = QWidget()
        picker_layout = QVBoxLayout(picker)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search captured artifacts and findings")
        self.search.setAccessibleName("Search graph nodes")
        picker_layout.addWidget(self.search)
        self.node_list = QListWidget()
        self.node_list.setAccessibleName("Graph focus: activate a result to show its neighborhood")
        picker_layout.addWidget(self.node_list)
        focus = QPushButton("Focus selected result")
        focus.clicked.connect(self.focus_result)
        picker_layout.addWidget(focus)
        add = QPushButton("Add selected result")
        add.clicked.connect(self.add_result)
        picker_layout.addWidget(add)
        splitter.addWidget(picker)
        self.scene = QGraphicsScene(self)
        self.view = GraphView(self.scene)
        splitter.addWidget(self.view)
        self.inspector = QTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setAccessibleName("Artifact and relationship provenance")
        splitter.addWidget(self.inspector)
        splitter.setSizes([230, 600, 280])
        layout.addWidget(splitter, 3)
        self.relationships = QTableWidget(0, 4)
        self.relationships.setHorizontalHeaderLabels(["Source →", "Relationship", "Target", "Kind"])
        self.relationships.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.relationships.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.relationships.setAccessibleName("Relationships in the visible graph")
        self.relationships.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.relationships, 1)
        self.status = QLabel("Open a case to explore recorded relationships.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.run_choice.currentIndexChanged.connect(self.load_run)
        self.search.textChanged.connect(self.filter_nodes)
        self.node_list.itemActivated.connect(lambda _: self.focus_result())
        self.scene.selectionChanged.connect(self.inspect_selection)
        self.relationships.currentCellChanged.connect(self.inspect_relationship)
        self._visible_edges = []

    def open_case(self, workspace: str, case: Case) -> None:
        if self.workspace_path == workspace and self.case == case:
            return
        self.workspace_path, self.case = workspace, case
        self.refresh()

    def refresh(self) -> None:
        previous = self.run_choice.currentData()
        self.run_choice.blockSignals(True)
        self.run_choice.clear()
        try:
            if self.case:
                database = workspace_database(self.workspace_path)
                for evidence in EvidenceRepository(database).list_by_case(self.case.id):
                    for run in reversed(AnalysisRunRepository(database).list_by_evidence(evidence.id)):
                        self.run_choice.addItem(
                            f"{evidence.file_path.name} · {run.id} · {run.status}", str(run.id))
                index = self.run_choice.findData(previous)
                if index >= 0:
                    self.run_choice.setCurrentIndex(index)
        except Exception as exc:
            self.status.setText(f"Could not load analysis runs: {exc}")
            return
        finally:
            self.run_choice.blockSignals(False)
        self.load_run()

    def load_run(self) -> None:
        self.graph = InvestigationGraph()
        self.visible = set()
        self.inspector.clear()
        self.search.clear()
        try:
            if run_id := self.run_choice.currentData():
                self.graph = load_graph(workspace_database(self.workspace_path), UUID(run_id))
        except Exception as exc:
            self.graph.warnings.append(f"Could not load graph: {exc}")
        self.filter_nodes()
        seeds = sorted(self.graph.nodes, key=lambda key: (
            self.graph.nodes[key].kind != "finding",
            self.graph.nodes[key].kind != "process", key))
        if seeds:
            self.visible = self.graph.neighborhood({seeds[0]})
        self.render_graph()

    def filter_nodes(self) -> None:
        self.node_list.clear()
        query = self.search.text().casefold()
        for node in sorted(self.graph.nodes.values(), key=lambda n: (n.kind, n.label, n.id)):
            if query in f"{node.kind} {node.label} {node.id}".casefold():
                item = QListWidgetItem(f"{node.kind.replace('_', ' ')} · {node.label}")
                item.setData(Qt.ItemDataRole.UserRole, node.id)
                self.node_list.addItem(item)

    def focus_result(self) -> None:
        if item := self.node_list.currentItem():
            key = item.data(Qt.ItemDataRole.UserRole)
            self.visible = self.graph.neighborhood({key})
            self.render_graph()
            self.node_items[key].setSelected(True)

    def add_result(self) -> None:
        if item := self.node_list.currentItem():
            self.visible.add(item.data(Qt.ItemDataRole.UserRole))
            self.render_graph()

    def expand_selected(self) -> None:
        seeds = {item.data(0) for item in self.scene.selectedItems() if item.data(0)}
        if seeds:
            self.visible |= self.graph.neighborhood(seeds, existing=self.visible)
            self.render_graph()

    def render_graph(self) -> None:
        positions = {key: item.pos() for key, item in self.node_items.items()}
        self.edge_items = []
        self.node_items = {}
        self.scene.clear()
        self._visible_edges = [e for e in self.graph.edges
                               if e.source in self.visible and e.target in self.visible]
        for index, key in enumerate(sorted(self.visible)):
            node = self.graph.nodes[key]
            item = NodeItem(key, self)
            item.setBrush(QColor("#fff3cd" if node.kind == "finding" else "#dbeafe"))
            item.setPen(QPen(QColor("#2563eb"), 2))
            self.scene.addItem(item)
            label = self.scene.addText(f"{node.kind.replace('_', ' ')}\n{node.label}")
            label.setDefaultTextColor(QColor("#172033"))
            label.setTextWidth(210)
            label.setParentItem(item)
            label.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
            item.setToolTip(node.label)
            item.setZValue(1)
            item.setPos(positions.get(key, QPointF((index % 4) * 330, (index // 4) * 150)))
            self.node_items[key] = item
        self.relationships.setRowCount(len(self._visible_edges))
        for row, edge in enumerate(self._visible_edges):
            pen = QPen(QColor("#64748b"), 2,
                       Qt.PenStyle.DashLine if edge.kind == "inferred" else Qt.PenStyle.SolidLine)
            line = self.scene.addLine(QLineF(), pen)
            line.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
            line.setData(1, row)
            line.setToolTip(f"{edge.kind}: {edge.label}")
            arrow = self.scene.addPolygon(QPolygonF(), pen, QColor("#64748b"))
            label = self.scene.addText(edge.label)
            label.setDefaultTextColor(self.palette().text().color())
            self.edge_items.append((edge, line, arrow, label))
            for col, value in enumerate((self.graph.nodes[edge.source].label, edge.label,
                                         self.graph.nodes[edge.target].label, edge.kind)):
                self.relationships.setItem(row, col, QTableWidgetItem(value))
        self.update_edges()
        self.status.setText(
            f"{len(self.visible)} / {len(self.graph.nodes)} nodes · "
            f"{len(self._visible_edges)} visible relationships. Expand adds up to 40 neighbors. "
            "Unresolved ownership is left unlinked. " + " ".join(self.graph.warnings[:5])
            if self.graph.nodes else "No captured artifacts or findings for this run. "
            + " ".join(self.graph.warnings)
        )
        self.fit_view()

    def update_edges(self) -> None:
        for edge, line, arrow, label in self.edge_items:
            start = self.node_items[edge.source].sceneBoundingRect().center()
            end = self.node_items[edge.target].sceneBoundingRect().center()
            delta = end - start
            # End arrows at the target rectangle boundary rather than behind the node.
            scale = min(110 / abs(delta.x()) if delta.x() else float("inf"),
                        32 / abs(delta.y()) if delta.y() else float("inf"))
            tip = end - delta * min(scale, 0.5)
            line.setLine(QLineF(start, tip))
            angle = math.atan2(delta.y(), delta.x())
            arrow.setPolygon(QPolygonF([tip, tip - QPointF(math.cos(angle - .45) * 12,
                                                         math.sin(angle - .45) * 12),
                                       tip - QPointF(math.cos(angle + .45) * 12,
                                                     math.sin(angle + .45) * 12)]))
            label.setPos((start + end) / 2)

    def inspect_selection(self) -> None:
        selected = self.scene.selectedItems()
        if selected and (key := selected[0].data(0)) in self.graph.nodes:
            self.inspector.setPlainText(json.dumps(self.graph.nodes[key].details, indent=2))
        elif selected and selected[0].data(1) is not None:
            self.inspect_relationship(selected[0].data(1))

    def inspect_relationship(self, row: int, *_args) -> None:
        if 0 <= row < len(self._visible_edges):
            edge = self._visible_edges[row]
            self.inspector.setPlainText(
                f"{edge.kind.upper()} · {edge.label}\n{edge.source} → {edge.target}\n\n"
                + json.dumps(edge.details, indent=2))

    def fit_view(self) -> None:
        if self.node_items:
            self.view.fitInView(self.scene.itemsBoundingRect().adjusted(-40, -40, 40, 40),
                                Qt.AspectRatioMode.KeepAspectRatio)

    def fit_selection(self) -> None:
        selected = self.scene.selectedItems()
        if selected:
            bounds = selected[0].sceneBoundingRect()
            for item in selected[1:]:
                bounds = bounds.united(item.sceneBoundingRect())
            self.view.fitInView(bounds.adjusted(-80, -80, 80, 80),
                                Qt.AspectRatioMode.KeepAspectRatio)


def create_page() -> InvestigationGraphPage:
    return InvestigationGraphPage()
