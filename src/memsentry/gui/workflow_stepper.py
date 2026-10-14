"""Compact workflow rail with persisted SHA-256 transition checkpoints."""

from functools import lru_cache
from pathlib import Path
from typing import Any

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.workflow_service import STAGES
from memsentry.models.analysis_run import AnalysisRun
from memsentry.models.case import Case
from memsentry.models.evidence import Evidence

ASSETS = Path(__file__).resolve().parent / "assets"
STATUS_LABELS = {
    "completed": "Complete",
    "running": "In progress",
    "ready": "Up next",
    "failed": "Failed",
    "pending": "Pending",
    "untracked": "Not recorded",
}


@lru_cache(maxsize=128)
def _icon(name: str, color: str, size: int, ratio: float) -> QPixmap:
    """Render the shared vector assets at the current display scale and palette."""
    svg = (ASSETS / f"{name}.svg").read_text(encoding="utf-8")
    renderer = QSvgRenderer(QByteArray(svg.replace("currentColor", color).encode()))
    pixmap = QPixmap(round(size * ratio), round(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return pixmap


class WorkflowStepper(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)
        header = QHBoxLayout()
        heading = QLabel("Investigation workflow")
        heading.setStyleSheet("font-size: 14px; font-weight: 600;")
        header.addWidget(heading)
        header.addStretch()
        self.summary = QLabel()
        self.summary.setObjectName("muted")
        header.addWidget(self.summary)
        layout.addLayout(header)
        scroll = QScrollArea()
        scroll.setObjectName("workflowScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFixedHeight(126)
        self.rail_scroll = scroll
        rail = QWidget()
        rail.setMinimumWidth(850)
        row = QHBoxLayout(rail)
        row.setContentsMargins(0, 4, 0, 0)
        row.setSpacing(0)
        self.nodes = []
        self.gates = []
        self.lines = []
        self.status_labels = []
        for index, name in enumerate(STAGES):
            node = QWidget()
            column = QVBoxLayout(node)
            node.setMinimumWidth(84)
            column.setContentsMargins(2, 0, 2, 0)
            column.setSpacing(6)
            circle = QLabel()
            circle.setFixedSize(44, 44)
            circle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            caption = QLabel(name.title())
            caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
            column.addWidget(circle, alignment=Qt.AlignmentFlag.AlignHCenter)
            column.addWidget(caption)
            status = QLabel()
            status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            column.addWidget(status)
            self.status_labels.append(status)
            column.addStretch()
            row.addWidget(node)
            self.nodes.append((circle, caption))
            if index < len(STAGES) - 1:
                connector = QWidget()
                connector_layout = QVBoxLayout(connector)
                connector_layout.setContentsMargins(4, 21, 4, 0)
                connector_layout.setSpacing(10)
                line = QFrame()
                line.setFixedHeight(1)
                connector_layout.addWidget(line)
                gate = QLabel()
                gate.setAlignment(Qt.AlignmentFlag.AlignCenter)
                gate.setFixedSize(18, 18)
                connector_layout.addWidget(gate, alignment=Qt.AlignmentFlag.AlignHCenter)
                connector_layout.addStretch()
                row.addWidget(connector, 1)
                self.gates.append(gate)
                self.lines.append(line)
        scroll.setWidget(rail)
        layout.addWidget(scroll)
        self.detail = QLabel("Create or open a case to begin.")
        self.detail.setObjectName("muted")
        self.detail.setWordWrap(True)
        layout.addWidget(self.detail)
        self.states = ["pending"] * 8
        self.checkpoints = ["pending"] * 7
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        app.paletteChanged.connect(self._paint_states)
        self._paint_states()

    def text(self) -> str:
        return self.detail.text()

    def show_records(
        self,
        case: Case | None,
        evidence: Evidence | None,
        run: AnalysisRun | None,
        events: list[dict[str, Any]],
    ) -> None:
        self.states = ["pending"] * 8
        self.checkpoints = ["pending"] * 7
        self.checkpoints[0] = "na"  # No image exists yet between case creation and acquisition.
        if case:
            self.states[0] = "completed"
            self.states[1] = "ready"
        if evidence:
            self.states[1] = "completed"
            self.states[2] = "ready"
        latest = {}
        gate_events = {}
        for event in events:
            latest[(event["stage"], event["phase"])] = event
        for index, stage in enumerate(STAGES):
            operation = latest.get((stage, "operation"))
            if operation:
                self.states[index] = operation["status"]
            before = latest.get((stage, "before"))
            after = latest.get((stage, "after"))
            if before and index > 0:
                self.checkpoints[index - 1] = before["status"]
                gate_events[index - 1] = before
                if before["status"] == "running":
                    self.states[index] = "running"
            if after and index < 7:
                self.checkpoints[index] = after["status"]
                gate_events[index] = after
            if (before and before["status"] == "failed") or (after and after["status"] == "failed"):
                self.states[index] = "failed"
        # Old analysis status alone is not proof of a successful integrity gate.
        if run and not any(stage == "analyze" for stage, _ in latest):
            self.states[3] = "running" if run.status == "running" else "untracked"
        if evidence and evidence.integrity_status != "verified" and "failed" not in self.states:
            self.states[2] = "failed"
            self.checkpoints[1] = "failed"
        if "failed" in self.states:
            failed_index = self.states.index("failed")
            for index in range(failed_index + 1, 8):
                self.states[index] = "pending"
                if index < 7:
                    self.checkpoints[index] = "pending"
        for index in range(1, 8):
            if (
                "failed" not in self.states
                and self.states[index] == "pending"
                and self.states[index - 1] == "completed"
            ):
                self.states[index] = "ready"
                break
        message = "Create or open a case to begin." if not case else "Ready for the next stage."
        if events:
            event = events[-1]
            parts = [event["stage"].title()]
            if event["phase"] != "operation":
                parts.append("Integrity check")
            parts.append(STATUS_LABELS.get(event["status"], event["status"]))
            if event["status"] == "running":
                parts.append(f"{event['progress']}%")
            if event.get("message"):
                parts.append(event["message"].replace("SHA-256", "Integrity"))
            message = " · ".join(parts)
        if evidence and evidence.integrity_status != "verified":
            message = f"Evidence {evidence.integrity_status} — workflow blocked. Original baseline retained."
        self.detail.setText(message)
        for index, gate in enumerate(self.gates):
            gate_event = gate_events.get(index)
            gate.setToolTip(
                "No evidence image exists before acquisition; SHA-256 is not applicable."
                if index == 0
                else "Fresh SHA-256 checks run before and after supported operations. "
                "A mismatch blocks advancement. Unconnected operations stay pending."
            )
            if gate_event:
                gate.setToolTip(
                    gate.toolTip()
                    + f"\n{gate_event.get('created_at', '')} · {gate_event['phase']} · {gate_event['status']}"
                    f"\nExpected: {gate_event.get('expected_sha256') or 'Not recorded'}"
                    f"\nActual: {gate_event.get('actual_sha256') or 'Not yet available'}"
                )
        self._paint_states()

    def _paint_states(self) -> None:
        dark = QApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128
        blue = "#60A5FA" if dark else "#2563EB"
        muted = "#A5B0C0" if dark else "#526174"
        text = "#E5E7EB" if dark else "#172033"
        border = "#3D4858" if dark else "#DCE3EC"
        neutral_fill = "#232B37" if dark else "#F8FAFC"
        complete_fill = "#20334F" if dark else "#E8F0FE"
        self.rail_scroll.setStyleSheet(f"""
            QScrollBar:horizontal {{ height: 8px; background: transparent; margin: 0; }}
            QScrollBar::handle:horizontal {{ background: {border}; min-width: 32px; border-radius: 4px; }}
            QScrollBar::handle:horizontal:hover {{ background: {muted}; }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}
        """)
        colors = {
            "completed": blue,
            "running": blue,
            "ready": text,
            "failed": text,
            "pending": muted,
            "untracked": muted,
            "na": muted,
        }
        for index, ((circle, caption), state) in enumerate(
            zip(self.nodes, self.states, strict=True)
        ):
            color = colors[state]
            circle.setPixmap(_icon(STAGES[index], color, 24, self.devicePixelRatioF()))
            fill = complete_fill if state == "completed" else neutral_fill
            outline = color if state in ("completed", "running", "failed") else border
            circle.setStyleSheet(
                f"QLabel {{ border: 1px solid {outline}; border-radius: 12px; "
                f"background: {fill}; }}"
            )
            caption.setStyleSheet(
                f"QLabel {{ color: {color}; font-size: 12px; font-weight: 600; }}"
            )
            status = self.status_labels[index]
            status.setText(
                "" if state == "pending" else STATUS_LABELS[state]
            )
            status.setStyleSheet(
                f"QLabel {{ color: {blue if state in ('completed', 'running') else muted}; "
                f"font-size: 10px; }}"
            )
            circle.setToolTip(f"{STAGES[index].title()}: {state}")
            circle.setAccessibleName(f"{STAGES[index].title()}: {state}")
        completed = self.states.count("completed")

        self.summary.setText(f"{self.states.count('completed')} of {len(STAGES)} complete")
        for gate, line, state in zip(self.gates, self.lines, self.checkpoints, strict=True):
            gate.clear()
            if state == "completed":
                gate.setPixmap(_icon("verified_badge", blue, 16, self.devicePixelRatioF()))
            else:
                gate.setText({"running": "…", "failed": "!"}.get(state, ""))
            gate.setAccessibleName(f"Integrity checkpoint: {state}")
            line.setStyleSheet(
                f"background: {blue if state == 'completed' else border}; border: none;"
            )
            gate.setStyleSheet(f"QLabel {{ color: {muted}; font-size: 12px; font-weight: 600; }}")
