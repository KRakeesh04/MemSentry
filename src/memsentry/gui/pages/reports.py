"""Reports page preview."""

from PySide6.QtWidgets import QScrollArea

from memsentry.gui.pages.placeholder import create_placeholder

CONTENT = (
    "Export findings with provenance and integrity records.",
    [("JSON", "Structured results"), ("HTML", "Readable report")],
    "Report contents",
    ["Section", "Status"],
    [
        ["Evidence and hashes", "Awaiting analysis"],
        ["Automated findings", "Awaiting analysis"],
        ["Investigator revision", "None selected"],
    ],
    "Generate report",
)


def create_page() -> QScrollArea:
    return create_placeholder("Reports", CONTENT)
