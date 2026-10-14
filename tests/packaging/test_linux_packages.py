from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from scripts.package_linux import build_appimage, build_deb, debian_architecture


def test_debian_architecture_names() -> None:
    assert debian_architecture("x86_64") == "amd64"
    assert debian_architecture("aarch64") == "arm64"
    with pytest.raises(ValueError, match="Unsupported Debian architecture"):
        debian_architecture("i686")


def test_debian_package_contains_bundle_launcher_and_desktop_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "MemSentry").write_bytes(b"synthetic executable")
    (bundle / "_internal").mkdir()
    (bundle / "_internal" / "resource.dat").write_text("fixture", encoding="utf-8")
    icon = tmp_path / "build/icons/memsentry.png"
    icon.parent.mkdir(parents=True)
    icon.write_bytes(b"synthetic icon")

    package = build_deb(bundle, "0.1.0", tmp_path / "release", "x86_64")

    fields = subprocess.run(
        ["dpkg-deb", "--field", str(package)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    metadata = dict(line.split(": ", maxsplit=1) for line in fields if ": " in line)
    members = subprocess.run(
        ["dpkg-deb", "--contents", str(package)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert metadata["Package"] == "memsentry"
    assert metadata["Version"] == "0.1.0"
    assert metadata["Architecture"] == "amd64"
    assert "/opt/memsentry/MemSentry" in members
    assert "/usr/bin/memsentry" in members
    assert "/usr/share/applications/memsentry.desktop" in members


def test_appimage_stages_complete_bundle_and_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "MemSentry").write_bytes(b"synthetic executable")
    (bundle / "_internal").mkdir()
    (bundle / "_internal" / "resource.dat").write_text("fixture", encoding="utf-8")
    icon = tmp_path / "build/icons/memsentry.png"
    icon.parent.mkdir(parents=True)
    icon.write_bytes(b"synthetic icon")
    tool = tmp_path / "appimagetool"
    tool.write_text("fixture", encoding="utf-8")
    observed: dict[str, object] = {}

    def fake_appimagetool(
        command: list[str], *, check: bool, env: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        appdir = Path(command[1])
        destination = Path(command[2])
        observed["check"] = check
        observed["architecture"] = env["ARCH"]
        observed["launcher"] = (appdir / "AppRun").read_text(encoding="utf-8")
        observed["desktop"] = (appdir / "memsentry.desktop").read_text(encoding="utf-8")
        observed["bundle_file"] = (
            appdir / "usr/lib/memsentry/_internal/resource.dat"
        ).read_text(encoding="utf-8")
        destination.write_bytes(b"synthetic appimage")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("scripts.package_linux.subprocess.run", fake_appimagetool)
    package = build_appimage(bundle, "0.1.0", tmp_path / "release", tool, "x86_64")

    assert package.is_file()
    assert package.stat().st_mode & 0o111
    assert observed["check"] is True
    assert observed["architecture"] == "x86_64"
    assert "usr/lib/memsentry/MemSentry" in str(observed["launcher"])
    assert "Exec=AppRun" in str(observed["desktop"])
    assert observed["bundle_file"] == "fixture"
