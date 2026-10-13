"""Compatibility factory for the page-specific preview modules."""

from PySide6.QtWidgets import QWidget

from memsentry.gui.pages import PLACEHOLDER_PAGES


def create_sample_page(name: str) -> QWidget:
    if name == "Evidence & Analysis":
        from memsentry.gui.pages.evidence import EvidencePage

        return EvidencePage()
    return PLACEHOLDER_PAGES[name]()
