"""Interactive source cards, local file drop target, and host details."""

import getpass
import platform
import time
from pathlib import Path

import psutil
from PySide6.QtCore import QMimeData, Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import QFrame, QGridLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class ChoiceCard(QPushButton):
    def __init__(self, title: str, description: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("choiceCard")
        self.setCheckable(True)
        self.setAccessibleName(title)
        self.setAccessibleDescription(description)
        self.setMinimumHeight(76)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("choiceTitle")
        self.description_label = QLabel(description)
        self.description_label.setObjectName("muted")
        for label in (self.title_label, self.description_label):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            layout.addWidget(label)


class FileDropArea(QPushButton):
    file_selected = Signal(str)
    invalid_drop = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            "↑\n\nDrop a memory dump here, or click to select\n\n"
            "Common formats: .raw · .dmp · .vmem · .mem · .lime · .bin",
            parent,
        )
        self.setObjectName("fileDropArea")
        self.setAccessibleName("Select or drop one memory image")
        self.setMinimumHeight(184)
        self.setAcceptDrops(True)

    @staticmethod
    def local_file(mime: QMimeData | None) -> str | None:
        if mime is None:
            return None
        urls = mime.urls()
        if len(urls) == 1 and urls[0].isLocalFile():
            path = Path(urls[0].toLocalFile())
            if path.is_file():
                return str(path)
        return None

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if self.isEnabled() and self.local_file(event.mimeData()):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        path = self.local_file(event.mimeData())
        if self.isEnabled() and path:
            self.file_selected.emit(path)
            event.acceptProposedAction()
        else:
            event.ignore()
            self.invalid_drop.emit(
                "Drop one local memory image file; folders and remote URLs are not supported."
            )


class SystemCard(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        layout = QGridLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        heading = QLabel("Detected system")
        heading.setObjectName("sectionTitle")
        layout.addWidget(heading, 0, 0, 1, 3)
        try:
            ram = f"{psutil.virtual_memory().total / 1024**3:.1f} GiB"
            seconds = max(0, int(time.time() - psutil.boot_time()))
            uptime = f"{seconds // 86400}d {(seconds // 3600) % 24}h {(seconds // 60) % 60}m"
        except (OSError, RuntimeError):
            ram, uptime = "Unavailable", "Unavailable"
        try:
            user = getpass.getuser()
        except (OSError, KeyError):
            user = "Unavailable"
        details = [
            ("HOSTNAME", platform.node()),
            ("OS", f"{platform.system()} {platform.release()}"),
            ("ARCHITECTURE", platform.machine()),
            ("TOTAL RAM", ram),
            ("UPTIME", uptime),
            ("USER", user),
        ]
        for index, (name, value) in enumerate(details):
            row, col = 1 + (index // 3) * 2, index % 3
            caption, content = QLabel(name), QLabel(value or "Unavailable")
            caption.setObjectName("muted")
            content.setTextFormat(Qt.TextFormat.PlainText)
            content.setWordWrap(True)
            content.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(caption, row, col)
            layout.addWidget(content, row + 1, col)
            layout.setColumnStretch(col, 1)
