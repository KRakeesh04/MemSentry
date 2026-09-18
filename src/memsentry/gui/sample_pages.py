"""Presentation-only pages containing synthetic preview data."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

PAGE_CONTENT = {
    "Cases": (
        "Organize evidence and investigations in one place.",
        [("Sample cases", "2"), ("Evidence images", "3"), ("Active jobs", "0")],
        "Recent cases", ["Case", "Name", "Status"],
        [["DEMO-001", "Workstation investigation", "Open"],
         ["DEMO-002", "Linux server review", "Open"]], "New case",
    ),
    "Overview": (
        "A summary of the selected investigation.",
        [("Selected case", "DEMO-001"), ("Sample findings", "2"), ("Integrity", "Not checked")],
        "Investigation summary", ["Area", "Sample details"],
        [["Evidence", "workstation-sample.raw"], ["Target OS", "Windows"],
         ["Analysis", "Preview only — no analysis has run"]], "Start analysis",
    ),
    "Evidence & Analysis": (
        "Load an existing image or capture memory from this host.",
        [("Load memory image", "Existing dump"), ("Live acquisition", "Capture host RAM")],
        "Analysis setup", ["Setting", "Sample selection"],
        [["Source", "No file selected"], ["Plugins", "OS-specific defaults"],
         ["YARA rules", "Optional"], ["SHA-256", "Pending baseline"]], "Select evidence",
    ),
    "Artifacts": (
        "Explore processes, commands, and connections captured in memory.",
        [("Processes", "2 sample rows"), ("Source", "Synthetic data")],
        "Process explorer", ["PID", "Process", "Captured command"],
        [["1200", "explorer.exe", "explorer.exe"],
         ["2400", "powershell.exe", "powershell.exe -File demo.ps1"]], None,
    ),
    "Findings": (
        "Review explanations and supporting evidence before drawing conclusions.",
        [("Automated findings", "2 examples"), ("Assessment", "Not a verdict")],
        "Sample findings", ["Finding", "Priority", "Evidence"],
        [["Executable private memory", "High · sample", "Process 2400"],
         ["Command with network activity", "Medium · sample", "Process 2400"]], None,
    ),
    "Investigation Graph": (
        "Explore relationships and preserve your own investigation revisions.",
        [("View", "Original baseline"), ("Saved revisions", "None")],
        "Relationship preview", ["Source", "Relationship", "Target"],
        [["explorer.exe", "Parent of · sample", "powershell.exe"],
         ["powershell.exe", "Command · sample", "demo.ps1"],
         ["Analyst hypothesis", "Manual link · example", "Process 2400"]], "Save revision",
    ),
    "Reports": (
        "Export findings with provenance and integrity records.",
        [("JSON", "Structured results"), ("HTML", "Readable report")],
        "Report contents", ["Section", "Status"],
        [["Evidence and hashes", "Awaiting analysis"], ["Automated findings", "Awaiting analysis"],
         ["Investigator revision", "None selected"]], "Generate report",
    ),
    "Activity": (
        "Follow job stages, integrity checks, and investigator actions.",
        [("Current job", "Idle"), ("Integrity checks", "Not run")],
        "Workflow preview", ["Stage", "Status"],
        [["Register evidence", "Pending"], ["Verify SHA-256", "Pending"],
         ["Extract artifacts", "Pending"], ["Correlate findings", "Pending"]], None,
    ),
    "Settings": (
        "Application preferences and integration setup.",
        [("Appearance", "System theme"), ("Storage", "Local workspace")],
        "Configuration preview", ["Preference", "Value"],
        [["Theme", "Follows the application palette"], ["Acquisition tools", "Not configured"],
         ["Symbol directory", "Not configured"]], None,
    ),
    "Help": (
        "A clear starting point for memory investigations.",
        [("Getting started", "Create a case"), ("Next step", "Add evidence")],
        "Quick guide", ["Step", "What to do"],
        [["1 · Evidence", "Load a dump or choose live acquisition"],
         ["2 · Analysis", "Review plugins and start the job"],
         ["3 · Investigation", "Review findings and relationships"],
         ["4 · Report", "Save a revision and export results"]], None,
    ),
}


def create_sample_page(name: str) -> QScrollArea:
    """Build a scrollable page; no preview action executes forensic work."""
    description, metrics, section, headers, rows, action = PAGE_CONTENT[name]
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setAccessibleName(name)
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(32, 32, 32, 32)
    layout.setSpacing(24)

    heading = QHBoxLayout()
    title = QLabel(name)
    title.setObjectName("pageTitle")
    heading.addWidget(title, 1)
    if action:
        button = QPushButton(action.replace("&", "&&"))
        button.setEnabled(False)
        button.setToolTip("UI preview — this action is not connected yet.")
        heading.addWidget(button)
    layout.addLayout(heading)
    subtitle = QLabel(description)
    subtitle.setObjectName("muted")
    subtitle.setWordWrap(True)
    layout.addWidget(subtitle)

    cards = QHBoxLayout()
    cards.setSpacing(16)
    for label, value in metrics:
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        caption = QLabel(label)
        caption.setObjectName("muted")
        caption.setWordWrap(True)
        content = QLabel(value)
        content.setObjectName("metric")
        content.setWordWrap(True)
        card_layout.addWidget(caption)
        card_layout.addWidget(content)
        cards.addWidget(card, 1)
    layout.addLayout(cards)

    section_label = QLabel(section)
    section_label.setObjectName("sectionTitle")
    layout.addWidget(section_label)
    table = QTableWidget(len(rows), len(headers))
    table.setAccessibleName(section)
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().hide()
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setShowGrid(False)
    table.setWordWrap(True)
    for row_index, row in enumerate(rows):
        for column, value in enumerate(row):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            table.setItem(row_index, column, item)
        table.setRowHeight(row_index, 52)
    table.setMinimumHeight(64 + 52 * len(rows))
    layout.addWidget(table)
    layout.addStretch()
    scroll.setWidget(page)
    return scroll
