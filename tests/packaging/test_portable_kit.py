import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from scripts.package_portable import build_portable


@pytest.fixture
def kit_inputs(tmp_path):
    for platform, executable in (("Linux", "MemSentry"), ("Windows", "MemSentry.exe")):
        bundle = tmp_path / platform
        (bundle / "_internal").mkdir(parents=True)
        (bundle / executable).write_bytes(b"synthetic application")
        (bundle / "_internal/library").write_bytes(b"synthetic library")
    assets = tmp_path / "assets"
    (assets / "dump_tools").mkdir(parents=True)
    (assets / "env").write_text("MEMSENTRY_WORKSPACE=.\n", encoding="utf-8")
    tools = []
    for name in ("avml", "winpmem.exe"):
        data = b"synthetic tool"
        (assets / "dump_tools" / name).write_bytes(data)
        tools.append({"file": name, "sha256": hashlib.sha256(data).hexdigest()})
    (assets / "tools.json").write_text(json.dumps({"tools": tools}), encoding="utf-8")
    # Existing workspace contents must never be copied into release kits.
    (assets / "cases").mkdir()
    (assets / "cases/private.raw").write_bytes(b"synthetic evidence")
    return tmp_path / "Linux", tmp_path / "Windows", assets


def test_kit_contains_both_apps_clean_workspace_and_verified_assets(tmp_path, kit_inputs):
    linux, windows, assets = kit_inputs
    archive = build_portable(linux, windows, "1.2.3", tmp_path / "out", assets)
    with zipfile.ZipFile(archive) as zipped:
        assert zipped.testzip() is None
        names = zipped.namelist()
        for name in (
            "Linux/MemSentry", "Windows/MemSentry.exe", "Linux/_internal/library",
            "Windows/_internal/library", "MemSentryCases/cases/", "MemSentryCases/symbols/",
            "MemSentryCases/settings/", "MemSentryCases/env",
            "MemSentryCases/dump_tools/avml", "Start-Linux.sh", "Start-Windows.cmd",
        ):
            assert f"MemSentry/{name}" in names
        rules_dir = Path(__file__).resolve().parents[2] / "resources/yara"
        rules = list(rules_dir.glob("*.yara")) + list(rules_dir.glob("*.yar"))
        assert rules
        for rule in rules:
            assert zipped.read(f"MemSentry/MemSentryCases/Rules/{rule.name}") == rule.read_bytes()
        assert not any("private.raw" in name for name in names)
        assert zipped.getinfo("MemSentry/Linux/MemSentry").external_attr >> 16 & 0o111
        manifest = json.loads(zipped.read("MemSentry/manifest.json"))
        for name, digest in manifest["sha256"].items():
            assert hashlib.sha256(zipped.read(f"MemSentry/{name}")).hexdigest() == digest
    with pytest.raises(FileExistsError):
        build_portable(linux, windows, "1.2.3", tmp_path / "out", assets)


def test_modified_tool_blocks_packaging(tmp_path, kit_inputs):
    linux, windows, assets = kit_inputs
    (assets / "dump_tools/avml").write_bytes(b"changed")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        build_portable(linux, windows, "1.2.3", tmp_path / "out", assets)
    assert not (tmp_path / "out").exists()


def test_missing_windows_build_blocks_incomplete_release(tmp_path, kit_inputs):
    linux, _, assets = kit_inputs
    with pytest.raises(ValueError, match="Incomplete application bundle"):
        build_portable(linux, tmp_path / "missing", "1.2.3", tmp_path / "out", assets)


def test_vendored_tools_match_recorded_local_hashes():
    assets = Path(__file__).resolve().parents[2] / "packaging/portable"
    tools = json.loads((assets / "tools.json").read_text(encoding="utf-8"))["tools"]
    for tool in tools:
        with (assets / "dump_tools" / tool["file"]).open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == tool["sha256"]
