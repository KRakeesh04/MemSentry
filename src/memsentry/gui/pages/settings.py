"""Settings page preview."""

from PySide6.QtWidgets import QScrollArea

from memsentry.gui.pages.placeholder import create_placeholder

CONTENT = (
    "Application preferences and integration setup.",
    [("Appearance", "System theme"), ("Storage", "Local workspace")],
    "Configuration preview",
    ["Preference", "Value"],
    [
        ["Theme", "Follows the application palette"],
        ["Acquisition tools", "Not configured"],
        ["Symbol directory", "Not configured"],
    ],
    None,
)


def create_page() -> QScrollArea:
    return create_placeholder("Settings", CONTENT)
