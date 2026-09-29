import pytest
from PySide6.QtCore import QMimeData, QSettings, QUrl

from memsentry.gui.intake_widgets import FileDropArea
from memsentry.gui.pages.evidence import EvidencePage


def test_drop_accepts_one_local_file_only(tmp_path):
    path = tmp_path / "test.mem"
    path.write_bytes(b"synthetic")
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(path))])
    assert FileDropArea.local_file(mime) == str(path)
    mime.setUrls([QUrl("https://example.com/test.mem")])
    assert FileDropArea.local_file(mime) is None
    mime.setUrls([QUrl.fromLocalFile(str(tmp_path))])
    assert FileDropArea.local_file(mime) is None
    mime.setUrls([QUrl.fromLocalFile(str(path))] * 2)
    assert FileDropArea.local_file(mime) is None


def test_cards_switch_mode_and_custom_tool_visibility(qtbot):
    page = EvidencePage()
    qtbot.addWidget(page)
    page.mode_buttons.button(1).click()
    assert page.mode.currentIndex() == 1
    assert page.import_fields.isHidden()
    page.tool_choices.button(page.custom_tool_id).setChecked(True)
    page._tool_selected(page.custom_tool_id)
    assert not page.custom_tool_row.isHidden()
    page.mode_buttons.button(0).click()
    assert page.live_fields.isHidden()


def test_selected_file_details_update(qtbot, tmp_path):
    page = EvidencePage()
    qtbot.addWidget(page)
    path = tmp_path / "test.mem"
    path.write_bytes(b"synthetic")
    page.drop_area.file_selected.emit(str(path))
    assert page.source.text() == str(path)
    assert "9 bytes" in page.file_details.text()


@pytest.mark.parametrize("custom", [False, True])
def test_tool_choice_is_forwarded_to_backend(qtbot, tmp_path, monkeypatch, custom):
    monkeypatch.setattr(
        "memsentry.gui.pages.evidence.QSettings",
        lambda *_: QSettings(str(tmp_path / "prefs.ini"), QSettings.Format.IniFormat),
    )
    monkeypatch.setattr("memsentry.acquisition.tool_catalog.platform.system", lambda: "Linux")
    configured = tmp_path / "configured-avml"
    configured.write_bytes(b"mock")
    configured.chmod(0o700)
    chosen = tmp_path / "chosen-avml"
    chosen.write_bytes(b"mock")
    chosen.chmod(0o700)
    monkeypatch.setenv("MEMSENTRY_AVML", str(configured))
    monkeypatch.setattr("memsentry.gui.pages.evidence.IntakeWorker.start", lambda _: None)
    page = EvidencePage()
    qtbot.addWidget(page)
    page.workspace.setText(str(tmp_path))
    page.case_number.setText("TEST")
    page.case_name.setText("Test")
    page.mode_buttons.button(1).click()
    page.authorized.setChecked(True)
    page.tool.setText(str(chosen))
    if custom:
        page.tool_choices.button(page.custom_tool_id).click()
    page.start.click()
    assert page.worker.request.tool_path == (chosen if custom else configured)
    assert page.worker.request.avml_modern is True
