import pytest
from PySide6.QtCore import QMimeData, QPoint, QSettings, Qt, QUrl
from PySide6.QtWidgets import QApplication

from memsentry.gui.intake_widgets import FileDropArea, SystemCard
from memsentry.gui.pages.evidence import EvidencePage
from memsentry.gui.theme import create_light_palette, workspace_stylesheet


@pytest.mark.parametrize("height", [720, 1080])
def test_tool_selection_keeps_upper_sections_in_place(qtbot, height):
    page = EvidencePage()
    qtbot.addWidget(page)
    page.setObjectName("workspace")
    page.setStyleSheet(workspace_stylesheet())
    page.resize(1600, height)
    page.mode.setCurrentIndex(1)
    configured = page.tool_choices.button(0)
    configured.setEnabled(True)
    configured.click()
    page.show()
    qtbot.wait(50)
    system = page.findChild(SystemCard)
    widgets = [page.mode_buttons.button(1), system, *page.tool_choices.buttons()]

    def positions():
        return [widget.mapTo(page.widget(), QPoint()) for widget in widgets]

    before = positions()
    page.tool_choices.button(page.custom_tool_id).setEnabled(True)
    page.tool_choices.button(page.custom_tool_id).click()
    qtbot.wait(50)
    assert positions() == before
    assert system.height() >= system.minimumSizeHint().height()
    configured.click()
    qtbot.wait(50)
    assert positions() == before


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


def test_copy_into_case_checkbox_is_clickable_in_light_theme(qtbot, qapp):
    previous_palette = qapp.palette()
    qapp.setPalette(create_light_palette())
    try:
        page = EvidencePage()
        qtbot.addWidget(page)
        page.setObjectName("workspace")
        page.setStyleSheet(workspace_stylesheet())
        page.resize(1100, 720)
        page.show()
        checkbox = page.copy_into_case
        qtbot.waitUntil(lambda: checkbox.isVisible() and checkbox.width() > 0)
        page.ensureWidgetVisible(checkbox)
        qtbot.wait(50)
        initial = checkbox.isChecked()
        indicator_point = checkbox.mapToGlobal(QPoint(8, checkbox.height() // 2))
        hit_widget = QApplication.widgetAt(indicator_point)
        assert hit_widget is checkbox
        qtbot.mouseClick(
            hit_widget,
            Qt.MouseButton.LeftButton,
            pos=hit_widget.mapFromGlobal(indicator_point),
        )
        assert checkbox.isChecked() != initial
        label_x = checkbox.fontMetrics().horizontalAdvance("Copy into case") + 32
        qtbot.mouseClick(
            checkbox, Qt.MouseButton.LeftButton,
            pos=QPoint(min(label_x, checkbox.width() - 2), checkbox.height() // 2),
        )
        assert checkbox.isChecked() == initial
    finally:
        qapp.setPalette(previous_palette)


def test_copy_checkbox_receives_light_theme_click_in_application(qtbot, qapp):
    from memsentry.gui.main_window import MainWindow

    previous_palette = qapp.palette()
    qapp.setPalette(create_light_palette())
    try:
        window = MainWindow()
        qtbot.addWidget(window)
        window.show()
        window.pages.setCurrentIndex(2)
        checkbox = window.evidence_page.copy_into_case
        window.evidence_page.ensureWidgetVisible(checkbox)
        qtbot.waitUntil(lambda: checkbox.isVisible() and checkbox.width() > 0)
        qtbot.wait(50)
        initial = checkbox.isChecked()
        point = checkbox.mapToGlobal(QPoint(8, checkbox.height() // 2))
        hit_widget = QApplication.widgetAt(point)
        assert hit_widget is checkbox
        qtbot.mouseClick(
            hit_widget,
            Qt.MouseButton.LeftButton,
            pos=hit_widget.mapFromGlobal(point),
        )
        assert checkbox.isChecked() != initial
    finally:
        qapp.setPalette(previous_palette)


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
