"""Overview page preview."""

from memsentry.gui.pages.placeholder import create_placeholder

CONTENT = (
    "A summary of the selected investigation.",
    [("Selected case", "DEMO-001"), ("Sample findings", "2"), ("Integrity", "Not checked")],
    "Investigation summary",
    ["Area", "Sample details"],
    [
        ["Evidence", "workstation-sample.raw"],
        ["Target OS", "Windows"],
        ["Analysis", "Preview only — no analysis has run"],
    ],
    "Start analysis",
)


def create_page():
    return create_placeholder("Overview", CONTENT)
