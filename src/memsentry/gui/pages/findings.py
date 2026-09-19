"""Findings page preview."""

from memsentry.gui.pages.placeholder import create_placeholder

CONTENT = (
    "Review explanations and supporting evidence before drawing conclusions.",
    [("Automated findings", "2 examples"), ("Assessment", "Not a verdict")],
    "Sample findings",
    ["Finding", "Priority", "Evidence"],
    [
        ["Executable private memory", "High · sample", "Process 2400"],
        ["Command with network activity", "Medium · sample", "Process 2400"],
    ],
    None,
)


def create_page():
    return create_placeholder("Findings", CONTENT)
