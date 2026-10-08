"""Render the existing SVG branding to PNG and a multi-resolution Windows ICO."""

import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QIODevice, QRectF, Qt
from PySide6.QtGui import QImage, QPainter
from PySide6.QtSvg import QSvgRenderer


def create_icons(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    renderer = QSvgRenderer(str(source))
    if not renderer.isValid():
        raise ValueError(f"Invalid application SVG: {source}")
    sizes = (16, 24, 32, 48, 64, 128, 256)
    frames = []
    for size in sizes:
        image = QImage(size, size, QImage.Format.Format_ARGB32)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        renderer.render(painter, QRectF(0, 0, size, size))
        painter.end()
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        if not image.save(buffer, "PNG"):
            raise RuntimeError("Could not render application icon.")
        frames.append(bytes(buffer.data()))
        if size == 256:
            (destination / "memsentry.png").write_bytes(frames[-1])
    offset = 6 + 16 * len(sizes)
    entries = []
    for size, frame in zip(sizes, frames, strict=True):
        entries.append(struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0,
                                   1, 32, len(frame), offset))
        offset += len(frame)
    (destination / "memsentry.ico").write_bytes(
        struct.pack("<HHH", 0, 1, len(sizes)) + b"".join(entries) + b"".join(frames))


if __name__ == "__main__":
    create_icons(Path(sys.argv[1]), Path(sys.argv[2]))
