"""Portable resource resolution and build orchestration without network installs."""

import importlib.util
import runpy
import struct
import sys
from pathlib import Path

from memsentry.resource_paths import resource_directory

ROOT = Path(__file__).resolve().parents[1]


def test_resource_paths_do_not_depend_on_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert (resource_directory() / "plugin_registry.json").is_file()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "bundle"), raising=False)
    assert resource_directory() == tmp_path / "bundle" / "resources"


def test_generated_icon_contains_all_sizes(qapp, tmp_path):
    from PySide6.QtGui import QIcon

    generator = runpy.run_path(str(ROOT / "packaging/icons.py"))["create_icons"]
    generator(ROOT / "src/memsentry/gui/assets/shield.svg", tmp_path)
    data = (tmp_path / "memsentry.ico").read_bytes()
    assert struct.unpack("<HHH", data[:6]) == (0, 1, 7)
    for size in (16, 24, 32, 48, 64, 128, 256):
        assert not QIcon(str(tmp_path / "memsentry.ico")).pixmap(size, size).isNull()
    assert not QIcon(str(tmp_path / "memsentry.png")).pixmap(256, 256).isNull()


def test_build_prepares_dependencies_then_checks_before_launch(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("memsentry_build_script", ROOT / "scripts/build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    environments = []
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "run", lambda command, **kw: calls.append((command, kw)))
    monkeypatch.setattr(module.venv.EnvBuilder, "create", lambda _, folder: environments.append(folder))
    monkeypatch.setattr(sys, "argv", ["build.py", "--run"])
    assert module.main() == 0
    assert environments == [tmp_path / "build/venv"]
    assert calls[0][0][1:5] == ["-m", "pip", "install", "-r"]
    assert calls[1][0][1:6] == ["-m", "pip", "install", "--no-deps", "-e"]
    assert "PyInstaller" in calls[2][0]
    assert calls[3][0][-1] == "--smoke-test"
    assert calls[3][1]["env"]["QT_QPA_PLATFORM"] == "offscreen"
    assert calls[3][1]["cwd"] != tmp_path
    assert len(calls[4][0]) == 1


def test_build_stops_when_dependency_setup_fails(tmp_path, monkeypatch):
    import subprocess

    spec = importlib.util.spec_from_file_location("memsentry_build_failure", ROOT / "scripts/build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module.venv.EnvBuilder, "create", lambda *_: None)
    monkeypatch.setattr(sys, "argv", ["build.py", "--run"])
    calls = []

    def fail(command, **kwargs):
        calls.append(command)
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(module, "run", fail)
    assert module.main() == 1
    assert len(calls) == 1
