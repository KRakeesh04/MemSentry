"""Help page preview."""

from memsentry.gui.pages.placeholder import create_placeholder

CONTENT = (
    "A clear starting point for memory investigations.",
    [("Getting started", "Create a case"), ("Next step", "Add evidence")],
    "Quick guide",
    ["Step", "What to do"],
    [
        ["1 · Evidence", "Load a dump or choose live acquisition"],
        ["2 · Analysis", "Review plugins and start the job"],
        ["3 · Investigation", "Review findings and relationships"],
        ["4 · Report", "Save a revision and export results"],
    ],
    None,
)


def create_page():
    return create_placeholder("Help", CONTENT)
