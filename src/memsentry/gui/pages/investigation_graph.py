"""Run-scoped investigation workspace with a separate, saved manual layer."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from uuid import UUID, uuid4

from PySide6.QtCore import QEvent, QLineF, QPointF, Qt
from PySide6.QtGui import QPen, QPolygonF
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsPolygonItem,
    QGraphicsScene,
    QGraphicsTextItem,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.case_service import workspace_database
from memsentry.app.graph_revision_service import compose_graph, edge_key, save_revision
from memsentry.app.graph_service import GraphEdge, InvestigationGraph, load_graph
from memsentry.gui.controls import ThemedComboBox
from memsentry.gui.graph_canvas import GraphView, NodeItem, graph_colors
from memsentry.models.case import Case
from memsentry.models.graph_revision import GraphDraft, HypothesisNode, ManualRelationship
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.graph_revision_repository import GraphRevisionRepository


class InvestigationGraphPage(QScrollArea):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.case: Case | None = None
        self.workspace_path = ""
        self.graph = InvestigationGraph()
        self.baseline = InvestigationGraph()
        self.draft = GraphDraft()
        self._saved = self.draft.model_copy(deep=True)
        self._history = [self.draft.model_copy(deep=True)]
        self._history_index = 0
        self._rendering = False
        self._moving = False
        self._run_id: str | None = None
        self._revision_id: str | None = None
        self.visible: set[str] = set()
        self.node_items: dict[str, NodeItem] = {}
        self.edge_items: list[tuple[GraphEdge, QGraphicsLineItem, QGraphicsPolygonItem,
                                    QGraphicsTextItem]] = []
        self.view: GraphView
        content = QWidget()
        content.setObjectName("investigationGraphContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(8)
        heading = QHBoxLayout()
        title = QLabel("Investigation Graph")
        title.setObjectName("pageTitle")
        heading.addWidget(title)
        heading.addStretch()
        self.save_button = QPushButton("Save revision")
        self.save_button.setEnabled(False)
        self.save_button.setObjectName("primaryAction")
        self.save_button.clicked.connect(self.save_dialog)
        heading.addWidget(self.save_button)
        layout.addLayout(heading)
        subtitle = QLabel("Explore suspicious findings, connect artifacts, and record hypotheses.")
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)
        self.run_choice = ThemedComboBox()
        self.run_choice.setAccessibleName("Evidence and analysis run")
        toolbar = QHBoxLayout()
        toolbar.addWidget(self.run_choice, 1)
        refresh = QPushButton("Refresh runs")
        refresh.clicked.connect(self.refresh)
        toolbar.addWidget(refresh)
        layout.addLayout(toolbar)
        revisions = QHBoxLayout()
        revisions.addWidget(QLabel("Graph version"))
        self.revision_choice = ThemedComboBox()
        self.revision_choice.setAccessibleName("Original graph or saved investigator revision")
        self.revision_choice.currentIndexChanged.connect(self.load_revision)
        revisions.addWidget(self.revision_choice, 1)
        self.changes = QLabel("Original baseline")
        self.changes.setObjectName("muted")
        self.changes.setWordWrap(True)
        revisions.addWidget(self.changes, 1)
        layout.addLayout(revisions)
        legend = QLabel("Solid → observed   ·   Dashed → automated inference   ·   Dotted → manual")
        legend.setToolTip("Links show associations, not a proven action chain. "
                          "Hypotheses are investigator notes.")
        legend.setWordWrap(True)
        legend.setObjectName("muted")
        layout.addWidget(legend)
        editing = QHBoxLayout()
        for text, callback in (("Add hypothesis", self.add_hypothesis_dialog),
                               ("Connect nodes", self.connect_dialog),
                               ("Add note", self.note_dialog),
                               ("Hide selected", self.hide_selected),
                               ("Undo", self.undo), ("Redo", self.redo)):
            button = QPushButton(text)
            button.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
            button.clicked.connect(callback)
            editing.addWidget(button)
        editing.addStretch()
        layout.addLayout(editing)
        controls = QHBoxLayout()
        for text, callback in (("Expand selected", self.expand_selected),
                               ("Fit view", self.fit_view), ("Fit selection", self.fit_selection),
                               ("Zoom +", lambda: self.view.zoom(1.2)),
                               ("Zoom -", lambda: self.view.zoom(1 / 1.2))):
            button = QPushButton(text)
            button.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
            button.clicked.connect(callback)
            controls.addWidget(button)
        layout.addLayout(controls)
        splitter = QSplitter()
        picker = QWidget()
        picker_layout = QVBoxLayout(picker)
        picker_layout.setContentsMargins(0, 0, 8, 0)
        picker_heading = QLabel("Artifacts & hypotheses")
        picker_heading.setObjectName("sectionTitle")
        picker_layout.addWidget(picker_heading)
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
        details = QWidget()
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(8, 0, 0, 0)
        details_heading = QLabel("Details & provenance")
        details_heading.setObjectName("sectionTitle")
        details_layout.addWidget(details_heading)
        details_layout.addWidget(self.inspector)
        splitter.addWidget(details)
        splitter.setSizes([220, 820, 260])
        splitter.setStretchFactor(1, 1)
        controls.addStretch()
        for text, panel, shown in (("Node picker", picker, True), ("Details", details, False)):
            toggle = QPushButton(text)
            toggle.setCheckable(True)
            toggle.setChecked(shown)
            panel.setVisible(shown)
            toggle.toggled.connect(panel.setVisible)
            controls.addWidget(toggle)
        layout.addWidget(splitter, 1)
        self.relationships = QTableWidget(0, 4)
        self.relationships.setHorizontalHeaderLabels(["Source →", "Relationship", "Target", "Kind"])
        self.relationships.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.relationships.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.relationships.setShowGrid(False)
        self.relationships.verticalHeader().hide()
        self.relationships.setAccessibleName("Relationships in the visible graph")
        self.relationships.horizontalHeader().setStretchLastSection(True)
        self.relationships.setMaximumHeight(120)
        self.relationships.setColumnWidth(0, 220)
        self.relationships.setColumnWidth(1, 180)
        self.relationships.setColumnWidth(2, 220)
        self.relationships.hide()
        relationships_toggle = QPushButton("Relationships")
        relationships_toggle.setCheckable(True)
        relationships_toggle.toggled.connect(self.relationships.setVisible)
        controls.addWidget(relationships_toggle)
        layout.addWidget(self.relationships)
        self.status = QLabel("Open a case to explore recorded relationships.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.run_choice.currentIndexChanged.connect(self.load_run)
        self.search.textChanged.connect(self.filter_nodes)
        self.node_list.itemActivated.connect(lambda _: self.focus_result())
        self.scene.selectionChanged.connect(self.inspect_selection)
        self.relationships.currentCellChanged.connect(self.inspect_relationship)
        self._visible_edges: list[GraphEdge] = []
        self.setWidget(content)

    def open_case(self, workspace: str, case: Case) -> bool:
        if self.workspace_path == workspace and self.case == case:
            return True
        if not self.confirm_discard():
            return False
        self._run_id = None
        self.workspace_path, self.case = workspace, case
        self.refresh(force=True)
        return True

    def refresh(self, force: bool = False) -> None:
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
        if (force or self.run_choice.currentData() != self._run_id
                or (not self.dirty and self._revision_id is None)):
            self.load_run(force=True)

    def load_run(self, *_args: int, force: bool = False) -> None:
        run_id = self.run_choice.currentData()
        if run_id == self._run_id and not force:
            return
        if self._run_id and not self.confirm_discard():
            self._set_combo(self.run_choice, self._run_id)
            return
        self._run_id = run_id
        self._revision_id = None
        self.graph = InvestigationGraph()
        self.visible = set()
        self.inspector.clear()
        self.search.clear()
        try:
            if run_id := self.run_choice.currentData():
                self.graph = load_graph(workspace_database(self.workspace_path), UUID(run_id))
        except Exception as exc:
            self.graph.warnings.append(f"Could not load graph: {exc}")
        self.baseline = self.graph
        self.draft = GraphDraft()
        self.node_items = {}
        self.edge_items = []
        self.filter_nodes()
        seeds = sorted(self.graph.nodes, key=lambda key: (
            self.graph.nodes[key].kind != "finding",
            self.graph.nodes[key].kind != "process", key))
        if seeds:
            self.visible = self.graph.neighborhood({seeds[0]})
        self.render_graph()
        self.reset_history()
        self.refresh_revisions()

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
            self.capture_edit()
            self.node_items[key].setSelected(True)

    def add_result(self) -> None:
        if item := self.node_list.currentItem():
            self.visible.add(item.data(Qt.ItemDataRole.UserRole))
            self.render_graph()
            self.capture_edit()

    def expand_selected(self) -> None:
        seeds = {item.data(0) for item in self.scene.selectedItems() if item.data(0)}
        if seeds:
            self.visible |= self.graph.neighborhood(seeds, existing=self.visible)
            self.render_graph()
            self.capture_edit()

    def render_graph(self) -> None:
        self._rendering = True
        positions = {key: QPointF(*pos) for key, pos in self.draft.positions.items()}
        positions.update({key: item.pos() for key, item in self.node_items.items()})
        self.edge_items = []
        self.node_items = {}
        self.scene.clear()
        self._visible_edges = [e for e in self.graph.edges
                               if e.source in self.visible and e.target in self.visible
                               and edge_key(e) not in self.draft.hidden_edges]
        # Lay out a directed neighborhood in columns; cycles share the last column.
        levels: dict[str, int] = {}
        remaining = set(self.visible)
        for level in range(len(remaining)):
            roots = {key for key in remaining if not any(
                e.target == key and e.source in remaining for e in self._visible_edges)}
            if not roots:
                roots = remaining.copy()
            levels.update(dict.fromkeys(roots, level))
            remaining -= roots
            if not remaining:
                break
        rows: dict[int, int] = {}
        for key in sorted(self.visible):
            node = self.graph.nodes[key]
            item = NodeItem(key, self)
            self.scene.addItem(item)
            item.setToolTip(node.label)
            item.setZValue(1)
            level = levels.get(key, 0)
            row = rows.get(level, 0)
            rows[level] = row + 1
            item.setPos(positions.get(key, QPointF(level * 360, row * 160)))
            self.node_items[key] = item
        self.relationships.setRowCount(len(self._visible_edges))
        for row, edge in enumerate(self._visible_edges):
            color = graph_colors(self.palette())["muted"]
            pen = QPen(color, 2, {"inferred": Qt.PenStyle.DashLine,
                                  "manual": Qt.PenStyle.DotLine}.get(
                                      edge.kind, Qt.PenStyle.SolidLine))
            line = self.scene.addLine(QLineF(), pen)
            line.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
            line.setData(1, row)
            line.setToolTip(f"{edge.kind}: {edge.label}")
            arrow = self.scene.addPolygon(QPolygonF(), pen, color)
            label = self.scene.addText(f"Manual: {edge.label}" if edge.kind == "manual" else edge.label)
            label.setDefaultTextColor(color)
            label.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
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
        self._rendering = False

    def update_edges(self) -> None:
        for edge, line, arrow, label in self.edge_items:
            start = self.node_items[edge.source].sceneBoundingRect().center()
            end = self.node_items[edge.target].sceneBoundingRect().center()
            delta = end - start
            # End arrows at the target rectangle boundary rather than behind the node.
            scale = min(120 / abs(delta.x()) if delta.x() else float("inf"),
                        48 / abs(delta.y()) if delta.y() else float("inf"))
            tip = end - delta * min(scale, 0.5)
            line.setLine(QLineF(start, tip))
            angle = math.atan2(delta.y(), delta.x())
            arrow.setPolygon(QPolygonF([tip, tip - QPointF(math.cos(angle - .45) * 12,
                                                         math.sin(angle - .45) * 12),
                                       tip - QPointF(math.cos(angle + .45) * 12,
                                                     math.sin(angle + .45) * 12)]))
            label.setPos((start + end) / 2 - QPointF(label.boundingRect().width() / 2, 25))

    def inspect_selection(self) -> None:
        selected = self.scene.selectedItems()
        if selected and (key := selected[0].data(0)) in self.graph.nodes:
            node = self.graph.nodes[key]
            self.inspector.setPlainText(
                f"{node.label}\n{node.kind.replace('_', ' ').upper()}\n\n"
                f"Investigator note: {self.draft.notes.get(key, 'None')}\n\n"
                + json.dumps(node.details, indent=2))
        elif selected and selected[0].data(1) is not None:
            self.inspect_relationship(selected[0].data(1))

    def inspect_relationship(self, row: int, *_args: int) -> None:
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

    @staticmethod
    def _set_combo(combo: ThemedComboBox, value: str | None) -> None:
        combo.blockSignals(True)
        combo.setCurrentIndex(combo.findData(value))
        combo.blockSignals(False)

    def snapshot(self) -> GraphDraft:
        self.draft.visible = set(self.visible)
        self.draft.positions.update({key: (item.pos().x(), item.pos().y())
                                     for key, item in self.node_items.items()})
        return self.draft.model_copy(deep=True)

    @property
    def dirty(self) -> bool:
        return self.snapshot() != self._saved

    def reset_history(self) -> None:
        self._saved = self.snapshot()
        self._history = [self._saved.model_copy(deep=True)]
        self._history_index = 0
        self.update_changes()

    def capture_edit(self) -> None:
        if self._rendering or self._moving:
            return
        current = self.snapshot()
        if current != self._history[self._history_index]:
            self._history = self._history[:self._history_index + 1]
            self._history.append(current)
            self._history_index += 1
        self.update_changes()

    def update_changes(self) -> None:
        self.changes.setText(
            f"{'Unsaved changes' if self.dirty else 'Saved revision' if self._revision_id else 'Original baseline'}"
            f" · {len(self.draft.nodes)} hypotheses · {len(self.draft.edges)} manual links"
            f" · {len(self.draft.notes)} notes · {len(self.draft.hidden_edges)} hidden links")
        self.save_button.setEnabled(bool(self._run_id))

    def apply_draft(self, draft: GraphDraft) -> None:
        graph = compose_graph(self.baseline, draft)
        self.draft = draft.model_copy(deep=True)
        self.graph = graph
        self.visible = set(draft.visible)
        self.node_items = {}
        self.edge_items = []
        self.render_graph()
        self.filter_nodes()
        self.update_changes()

    def undo(self) -> None:
        if self._history_index:
            self._history_index -= 1
            self.apply_draft(self._history[self._history_index])

    def redo(self) -> None:
        if self._history_index + 1 < len(self._history):
            self._history_index += 1
            self.apply_draft(self._history[self._history_index])

    def commit_draft(self, draft: GraphDraft) -> None:
        self.apply_draft(draft)
        self.capture_edit()

    def add_hypothesis(self, label: str, category: str, rationale: str) -> str:
        draft = self.snapshot()
        key = f"hypothesis:{uuid4()}"
        draft.nodes[key] = HypothesisNode(label=label.strip(), category=category.strip(),
                                          notes=rationale.strip())
        draft.visible.add(key)
        # New hypotheses get free space below the existing view.
        draft.positions[key] = (0, max((p[1] for p in draft.positions.values()), default=-160) + 160)
        self.commit_draft(draft)
        return key

    def connect_nodes(self, source: str, target: str, label: str, rationale: str) -> None:
        draft = self.snapshot()
        draft.edges.append(ManualRelationship(source=source, target=target,
                                               label=label.strip(), rationale=rationale.strip()))
        draft.visible.update((source, target))
        self.commit_draft(draft)

    def hide_selected(self) -> None:
        draft = self.snapshot()
        for item in self.scene.selectedItems():
            if key := item.data(0):
                draft.visible.discard(key)
            elif item.data(1) is not None:
                draft.hidden_edges.add(edge_key(self._visible_edges[item.data(1)]))
        if not self.scene.selectedItems() and self.relationships.currentRow() >= 0:
            draft.hidden_edges.add(edge_key(self._visible_edges[self.relationships.currentRow()]))
        self.commit_draft(draft)

    def form_dialog(self, title: str, fields: list[tuple[str, QWidget]],
                    action: Callable[[], object]) -> bool:
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setObjectName("analysisDialog")
        dialog.setMinimumWidth(460)
        form = QFormLayout(dialog)
        for label, widget in fields:
            widget.setAccessibleName(label)
            form.addRow(label, widget)
        error = QLabel()
        error.setWordWrap(True)
        form.addRow(error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.rejected.connect(dialog.reject)

        def accept() -> None:
            try:
                action()
            except Exception as exc:
                error.setText(str(exc))
                return
            dialog.accept()

        buttons.accepted.connect(accept)
        form.addRow(buttons)
        return dialog.exec() == QDialog.DialogCode.Accepted

    def add_hypothesis_dialog(self) -> None:
        if not self._run_id:
            self.status.setText("Select an analysis run before adding a hypothesis.")
            return
        name = QLineEdit()
        category = ThemedComboBox()
        category.addItems(["Process", "Network", "File", "User", "Other"])
        rationale = QTextEdit()
        rationale.setPlaceholderText("Why is this entity relevant? This is a manual hypothesis.")
        self.form_dialog("Add investigator hypothesis", [("Label", name), ("Type", category),
                                                         ("Rationale", rationale)],
                         lambda: self.add_hypothesis(name.text(), category.currentText(),
                                                     rationale.toPlainText()))

    def connect_dialog(self) -> None:
        if len(self.graph.nodes) < 2:
            self.status.setText("Add at least two nodes before creating a relationship.")
            return
        source, target = ThemedComboBox(), ThemedComboBox()
        selected = sorted(item.data(0) for item in self.scene.selectedItems() if item.data(0))
        for node in sorted(self.graph.nodes.values(), key=lambda n: (n.label, n.id)):
            text = f"{node.label} · {node.kind} · {node.id[-8:]}"
            source.addItem(text, node.id)
            target.addItem(text, node.id)
        source.setCurrentIndex(source.findData(selected[0]) if selected else 0)
        target.setCurrentIndex(target.findData(selected[1]) if len(selected) > 1 else 1)
        label = QLineEdit()
        label.setPlaceholderText("e.g. suspected download, contacted, spawned")
        rationale = QTextEdit()
        rationale.setPlaceholderText("Explain the association and supporting evidence.")
        self.form_dialog("Connect nodes · manual relationship",
                         [("From", source), ("To", target), ("Relationship type", label),
                          ("Rationale", rationale)],
                         lambda: self.connect_nodes(source.currentData(), target.currentData(),
                                                    label.text(), rationale.toPlainText()))

    def note_dialog(self) -> None:
        selected = [item.data(0) for item in self.scene.selectedItems() if item.data(0)]
        if len(selected) != 1:
            self.status.setText("Select one node to add or edit its investigator note.")
            return
        key = selected[0]
        note = QTextEdit()
        note.setPlainText(self.draft.notes.get(key, ""))

        def apply() -> None:
            draft = self.snapshot()
            if note.toPlainText().strip():
                draft.notes[key] = note.toPlainText().strip()
            else:
                draft.notes.pop(key, None)
            self.commit_draft(draft)
            self.node_items[key].setSelected(True)

        self.form_dialog("Investigator note", [("Note", note)], apply)

    def refresh_revisions(self) -> None:
        self.revision_choice.blockSignals(True)
        self.revision_choice.clear()
        self.revision_choice.addItem("Original baseline", None)
        try:
            if self._run_id:
                for revision in GraphRevisionRepository(workspace_database(self.workspace_path)).list_by_run(
                        UUID(self._run_id)):
                    self.revision_choice.addItem(
                        f"{revision.name} · {revision.investigator} · "
                        f"{revision.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}", str(revision.id))
            self.revision_choice.setCurrentIndex(self.revision_choice.findData(self._revision_id))
        except Exception as exc:
            self.status.setText(f"Could not load saved revisions: {exc}")
        finally:
            self.revision_choice.blockSignals(False)

    def load_revision(self) -> None:
        selected = self.revision_choice.currentData()
        if selected == self._revision_id:
            return
        if not self.confirm_discard():
            self._set_combo(self.revision_choice, self._revision_id)
            return
        try:
            if selected:
                if not self._run_id:
                    raise ValueError("Select an analysis run before opening a revision.")
                revisions = GraphRevisionRepository(workspace_database(self.workspace_path)).list_by_run(
                    UUID(self._run_id))
                draft = next(r.draft for r in revisions if str(r.id) == selected)
            else:
                seeds = sorted(self.baseline.nodes,
                               key=lambda key: (self.baseline.nodes[key].kind != "finding", key))
                draft = GraphDraft(visible=self.baseline.neighborhood({seeds[0]}) if seeds else set())
            self.apply_draft(draft)
            self._revision_id = selected
            self._set_combo(self.revision_choice, selected)
            self.reset_history()
        except Exception as exc:
            self.status.setText(f"Could not open revision: {exc}")
            self._set_combo(self.revision_choice, self._revision_id)

    def save_current(self, name: str, investigator: str) -> None:
        if not self._run_id:
            raise ValueError("Select an analysis run before saving a revision.")
        revision = save_revision(workspace_database(self.workspace_path), UUID(self._run_id),
                                 name, investigator, self.snapshot())
        self._revision_id = str(revision.id)
        self._saved = self.snapshot()
        self.refresh_revisions()
        self.update_changes()
        self.status.setText(f"Saved revision '{revision.name}' by {revision.investigator}.")

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.Type.PaletteChange and hasattr(self, "view"):
            color = graph_colors(self.palette())["muted"]
            for _edge, line, arrow, label in self.edge_items:
                pen = line.pen()
                pen.setColor(color)
                line.setPen(pen)
                arrow.setPen(pen)
                arrow.setBrush(color)
                label.setDefaultTextColor(color)
            self.scene.update()
            self.view.viewport().update()

    def save_dialog(self) -> bool:
        name, investigator = QLineEdit(), QLineEdit()
        name.setPlaceholderText("e.g. Suspicious PowerShell investigation")
        return self.form_dialog("Save investigation revision", [("Revision name", name),
                                                               ("Investigator", investigator)],
                                lambda: self.save_current(name.text(), investigator.text()))

    def confirm_discard(self) -> bool:
        if not self.dirty:
            return True
        choice = QMessageBox.question(
            self, "Unsaved graph changes", "Save your graph revision before leaving this investigation?",
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
        if choice == QMessageBox.StandardButton.Save:
            return self.save_dialog()
        return choice == QMessageBox.StandardButton.Discard


def create_page() -> InvestigationGraphPage:
    return InvestigationGraphPage()
