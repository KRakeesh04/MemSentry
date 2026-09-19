"""Artifacts page preview."""

from memsentry.gui.pages.placeholder import create_placeholder

CONTENT = (
    "Explore processes, commands, and connections captured in memory.",
    [("Processes", "2 sample rows"), ("Source", "Synthetic data")],
    "Process explorer",
    ["PID", "Process", "Captured command"],
    [
        ["1200", "explorer.exe", "explorer.exe"],
        ["2400", "powershell.exe", "powershell.exe -File demo.ps1"],
    ],
    None,
)


def create_page():
    return create_placeholder("Artifacts", CONTENT)
