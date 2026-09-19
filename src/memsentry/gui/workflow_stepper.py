"""Compact workflow rail with persisted SHA-256 transition checkpoints."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette
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


class WorkflowStepper(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        heading = QLabel("Investigation Workflow")
        heading.setObjectName("muted")
        layout.addWidget(heading)
        scroll = QScrollArea()
        scroll.setObjectName("workflowScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setFixedHeight(105)
        rail = QWidget()
        row = QHBoxLayout(rail)
        row.setSpacing(0)
        self.nodes = []
        self.gates = []
        self.lines = []
        for index, name in enumerate(STAGES):
            node = QWidget()
            column = QVBoxLayout(node)
            column.setContentsMargins(4, 8, 4, 4)
            column.setSpacing(8)
            circle = QLabel(str(index + 1))
            circle.setFixedSize(24, 24)
            circle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            caption = QLabel(name.title())
            caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
            column.addWidget(circle, alignment=Qt.AlignmentFlag.AlignHCenter)
            column.addWidget(caption)
            column.addStretch()
            row.addWidget(node)
            self.nodes.append((circle, caption))
            if index < len(STAGES) - 1:
                connector = QWidget()
                connector_layout = QVBoxLayout(connector)
                connector_layout.setContentsMargins(8, 20, 8, 4)
                connector_layout.setSpacing(15)
                line = QFrame()
                line.setFixedHeight(1)
                connector_layout.addWidget(line)
                gate = QLabel("SHA-256")
                gate.setAlignment(Qt.AlignmentFlag.AlignCenter)
                gate.setMinimumWidth(66)
                connector_layout.addWidget(gate)
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
        QApplication.instance().paletteChanged.connect(self._paint_states)
        self._paint_states()

    def text(self):
        return self.detail.text()

    def show_records(self, case, evidence, run, events):
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
        message = "Ready — completed checks are recorded results, not continuous verification."
        if events:
            event = events[-1]
            action = "SHA-256" if event["phase"] != "operation" else "Operation"
            message = (
                f"{event['stage'].title()} · {action} "
                f"{event['phase'] if event['phase'] != 'operation' else ''} · "
                f"{event['status']} · {event['progress']}% · {event['message']}"
            )
        if evidence and evidence.integrity_status != "verified":
            message = f"Evidence {evidence.integrity_status} — workflow blocked. Original baseline retained."
        self.detail.setText(message)
        for index, gate in enumerate(self.gates):
            event = gate_events.get(index)
            gate.setToolTip(
                "No evidence image exists before acquisition; SHA-256 is not applicable."
                if index == 0
                else "Fresh SHA-256 checks run before and after supported operations. "
                "A mismatch blocks advancement. Unconnected operations stay pending."
            )
            if event:
                gate.setToolTip(
                    gate.toolTip()
                    + f"\n{event.get('created_at', '')} · {event['phase']} · {event['status']}"
                    f"\nExpected: {event.get('expected_sha256') or 'Not recorded'}"
                    f"\nActual: {event.get('actual_sha256') or 'Not yet available'}"
                )
        self._paint_states()

    def _paint_states(self):
        dark = QApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128
        green = "#74C7A9" if dark else "#237657"
        blue = "#60A5FA" if dark else "#2563EB"
        muted = "#8895A7" if dark else "#607086"
        colors = {
            "completed": green,
            "running": blue,
            "ready": blue,
            "failed": "#D36565",
            "pending": muted,
            "untracked": muted,
            "na": muted,
        }
        for index, ((circle, caption), state) in enumerate(
            zip(self.nodes, self.states, strict=True)
        ):
            color = colors[state]
            circle.setText(
                "✓" if state == "completed" else "!" if state == "failed" else str(index + 1)
            )
            fill = "#377C65" if state == "completed" else "transparent"
            circle.setStyleSheet(
                f"QLabel {{ border: 1px solid {color}; border-radius: 12px; "
                f"background: {fill}; color: {'white' if state == 'completed' else color}; }}"
            )
            caption.setStyleSheet(f"QLabel {{ color: {color}; font-size: 11px; }}")
            circle.setToolTip(f"{STAGES[index].title()}: {state}")
            circle.setAccessibleName(f"{STAGES[index].title()}: {state}")
        for gate, line, state in zip(self.gates, self.lines, self.checkpoints, strict=True):
            symbol = {"completed": "✓", "running": "…", "failed": "!", "na": "N/A"}.get(state, "○")
            gate.setText(f"{symbol} SHA-256")
            line.setStyleSheet(f"background: {colors[state]}; border: none;")
            gate.setStyleSheet(f"QLabel {{ color: {colors[state]}; font-size: 10px; }}")
