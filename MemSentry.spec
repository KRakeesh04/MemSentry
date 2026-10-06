# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import runpy
import sys

from PyInstaller.utils.hooks import collect_all, copy_metadata

root = Path(SPECPATH)
icons = root / "build" / "icons"
runpy.run_path(str(root / "packaging" / "icons.py"))["create_icons"](
    root / "src" / "memsentry" / "gui" / "assets" / "shield.svg", icons)
vol_data, vol_binaries, vol_imports = collect_all("volatility3")
datas = vol_data + copy_metadata("memsentry") + [
    (str(root / "src/memsentry/storage/schema"), "memsentry/storage/schema"),
    (str(root / "src/memsentry/gui/assets"), "memsentry/gui/assets"),
    (str(root / "resources"), "resources"),
    (str(icons / "memsentry.png"), "memsentry/gui/assets"),
    (str(icons / "memsentry.ico"), "memsentry/gui/assets"),
]
a = Analysis(
    [str(root / "packaging/entry.py")],
    pathex=[str(root / "src")],
    binaries=vol_binaries,
    datas=datas,
    hiddenimports=vol_imports + ["yara"],
    hookspath=[str(root / "packaging/hooks")],
    excludes=["pytest", "IPython", "tkinter", "mypy", "ruff"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True, name="MemSentry",
    console=False, strip=False, upx=False,
    icon=str(icons / "memsentry.ico") if sys.platform == "win32" else None,
)
collection = COLLECT(exe, a.binaries, a.datas, name="MemSentry", strip=False, upx=False)
