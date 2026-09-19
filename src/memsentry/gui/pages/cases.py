"""Cases page preview."""

from memsentry.gui.pages.placeholder import create_placeholder

CONTENT = (
    "Organize evidence and investigations in one place.",
    [("Sample cases", "2"), ("Evidence images", "3"), ("Active jobs", "0")],
    "Recent cases",
    ["Case", "Name", "Status"],
    [
        ["DEMO-001", "Workstation investigation", "Open"],
        ["DEMO-002", "Linux server review", "Open"],
    ],
    "New case",
)


def create_page():
    return create_placeholder("Cases", CONTENT)
