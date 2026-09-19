"""Investigation Graph page preview."""

from memsentry.gui.pages.placeholder import create_placeholder

CONTENT = (
    "Explore relationships and preserve your own investigation revisions.",
    [("View", "Original baseline"), ("Saved revisions", "None")],
    "Relationship preview",
    ["Source", "Relationship", "Target"],
    [
        ["explorer.exe", "Parent of · sample", "powershell.exe"],
        ["powershell.exe", "Command · sample", "demo.ps1"],
        ["Analyst hypothesis", "Manual link · example", "Process 2400"],
    ],
    "Save revision",
)


def create_page():
    return create_placeholder("Investigation Graph", CONTENT)
