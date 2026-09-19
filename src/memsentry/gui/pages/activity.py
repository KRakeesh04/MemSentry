"""Activity page preview."""

from memsentry.gui.pages.placeholder import create_placeholder

CONTENT = (
    "Follow job stages, integrity checks, and investigator actions.",
    [("Current job", "Idle"), ("Integrity checks", "Not run")],
    "Workflow preview",
    ["Stage", "Status"],
    [
        ["Register evidence", "Pending"],
        ["Verify SHA-256", "Pending"],
        ["Extract artifacts", "Pending"],
        ["Correlate findings", "Pending"],
    ],
    None,
)


def create_page():
    return create_placeholder("Activity", CONTENT)
