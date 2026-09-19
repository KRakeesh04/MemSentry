"""Compatibility factory for the page-specific preview modules."""

from memsentry.gui.pages import PLACEHOLDER_PAGES


def create_sample_page(name: str):
    if name == "Evidence & Analysis":
        from memsentry.gui.pages.evidence import EvidencePage

        return EvidencePage()
    return PLACEHOLDER_PAGES[name]()
