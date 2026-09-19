"""Page factories; functional evidence intake is constructed separately."""

from memsentry.gui.pages import (
    activity,
    artifacts,
    cases,
    findings,
    help,
    investigation_graph,
    overview,
    reports,
    settings,
)

PLACEHOLDER_PAGES = {
    "Cases": cases.create_page,
    "Overview": overview.create_page,
    "Artifacts": artifacts.create_page,
    "Findings": findings.create_page,
    "Investigation Graph": investigation_graph.create_page,
    "Reports": reports.create_page,
    "Activity": activity.create_page,
    "Settings": settings.create_page,
    "Help": help.create_page,
}
