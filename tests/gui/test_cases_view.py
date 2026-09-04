from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest
from PySide6.QtWidgets import QApplication

from memsentry.gui.cases_view import CasesView
from memsentry.gui.create_case_dialog import CreateCaseDialog
from memsentry.models.case import Case, CaseStatus


def make_case(number: str = "CASE-001") -> Case:
    now = datetime.now(UTC)
    return Case(
        id=uuid4(),
        case_number=number,
        name="Investigation",
        description=None,
        status=CaseStatus.OPEN,
        created_at=now,
        updated_at=now,
    )


class FakeCaseRepository:
    def __init__(self, cases: list[Case] | None = None) -> None:
        self.cases = cases or []

    def list_all(self) -> list[Case]:
        return self.cases

    def get_by_id(self, case_id: Any) -> Case | None:
        return next((case for case in self.cases if case.id == case_id), None)

    def create(self, data: object) -> Case:
        case = make_case("CASE-002")
        self.cases.append(case)
        return case


@pytest.fixture
def app() -> QApplication:
    return cast(QApplication, QApplication.instance() or QApplication([]))


def test_empty_state(qtbot: Any, app: QApplication) -> None:
    view = CasesView(cast(Any, FakeCaseRepository()))
    qtbot.addWidget(view)

    assert "No investigations yet" in view.state_label.text()
    assert view.case_table.rowCount() == 0


def test_cases_are_displayed_and_opened(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    view = CasesView(cast(Any, FakeCaseRepository([case])))
    qtbot.addWidget(view)
    opened: list[Case] = []
    view.case_opened.connect(opened.append)

    view.case_table.selectRow(0)
    view.open_selected_case()

    item = view.case_table.item(0, 0)
    assert item is not None
    assert item.text() == "CASE-001"
    assert opened == [case]


def test_loading_error_state(qtbot: Any, app: QApplication) -> None:
    class FailingRepository:
        def list_all(self) -> list[Case]:
            raise RuntimeError("database unavailable")

    view = CasesView(cast(Any, FailingRepository()))
    qtbot.addWidget(view)

    assert "Unable to load cases" in view.state_label.text()


def test_create_dialog_creates_case_and_refreshes(qtbot: Any, app: QApplication) -> None:
    repository = FakeCaseRepository()
    view = CasesView(cast(Any, repository))
    qtbot.addWidget(view)

    dialog = CreateCaseDialog(cast(Any, repository), view)
    qtbot.addWidget(dialog)
    dialog.case_number_input.setText("CASE-002")
    dialog.name_input.setText("New investigation")
    dialog.create_case()
    view.load_cases()

    assert dialog.result() == dialog.DialogCode.Accepted
    assert view.case_table.rowCount() == 1
    item = view.case_table.item(0, 0)
    assert item is not None
    assert item.text() == "CASE-002"
