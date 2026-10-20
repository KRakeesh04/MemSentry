"""Assemble fresh platform builds and approved local tools into a portable kit."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def add_to_zip(archive: zipfile.ZipFile, path: Path, arcname: Path) -> None:
    """Store executable mode bits for Unix launchers even on Windows builders."""
    info = zipfile.ZipInfo(arcname.as_posix())
    info.compress_type = zipfile.ZIP_DEFLATED
    if path.is_dir():
        mode = 0o40755
        info.filename += "/"
        data = b""
    elif arcname == Path("MemSentry/Linux/MemSentry"):
        mode = 0o100755
        data = path.read_bytes()
    elif arcname.name in {"Start-Linux.sh", "avml"}:
        mode = 0o100755
        data = path.read_bytes()
    else:
        mode = 0o100644
        data = path.read_bytes()
    info.external_attr = mode << 16
    archive.writestr(info, data)


def build_portable(
    linux_bundle: Path,
    windows_bundle: Path,
    version: str,
    output_dir: Path,
    assets: Path = ROOT / "packaging/portable",
) -> Path:
    """Package only application builds and allow-listed assets, never existing cases."""
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Version must have the form major.minor.patch.")
    for bundle, executable in (
        (linux_bundle, "MemSentry"),
        (windows_bundle, "MemSentry.exe"),
    ):
        if not (bundle / executable).is_file() or not (bundle / "_internal").is_dir():
            raise ValueError(f"Incomplete application bundle: {bundle}")
    tools = json.loads((assets / "tools.json").read_text(encoding="utf-8"))["tools"]
    for tool in tools:
        name = tool["file"]
        if Path(name).name != name or "/" in name or "\\" in name:
            raise ValueError(f"Invalid tool filename: {name}")
        if sha256(assets / "dump_tools" / name) != tool["sha256"]:
            raise ValueError(f"SHA-256 mismatch for acquisition tool: {name}")

    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"MemSentry-{version}-portable-kit-x86_64.zip"
    if archive.exists():
        raise FileExistsError(f"Refusing to overwrite {archive}")
    with tempfile.TemporaryDirectory(prefix="memsentry-portable-") as temporary:
        root = Path(temporary) / "MemSentry"
        # Dereference PyInstaller library symlinks for Windows-friendly ZIP extraction.
        shutil.copytree(linux_bundle, root / "Linux")
        shutil.copytree(windows_bundle, root / "Windows")
        workspace = root / "MemSentryCases"
        for folder in ("cases", "symbols", "Rules", "dump_tools", "settings"):
            (workspace / folder).mkdir(parents=True)
        shutil.copy2(assets / "env", workspace / "env")
        shutil.copy2(assets / "tools.json", workspace / "dump_tools" / "tools.json")
        for tool in tools:
            target = workspace / "dump_tools" / tool["file"]
            shutil.copy2(assets / "dump_tools" / tool["file"], target)
            target.chmod(0o755)
        rules = sorted((ROOT / "resources/yara").glob("*.yara")) + sorted(
            (ROOT / "resources/yara").glob("*.yar")
        )
        if not rules:
            raise ValueError("The portable kit requires at least one YARA rule.")
        for rule in rules:
            shutil.copy2(rule, workspace / "Rules" / rule.name)
        (root / "Linux" / "MemSentry").chmod(0o755)
        launcher = root / "Start-Linux.sh"
        launcher.write_text(
            '#!/bin/sh\nset -eu\n'
            'ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
            'export MEMSENTRY_ENV_FILE="$ROOT/MemSentryCases/env"\n'
            'chmod u+x "$ROOT/Linux/MemSentry" "$ROOT/MemSentryCases/dump_tools/avml"\n'
            'exec "$ROOT/Linux/MemSentry" "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(0o755)
        (root / "Start-Windows.cmd").write_bytes(
            b'@echo off\r\nsetlocal\r\n'
            b'set "MEMSENTRY_ENV_FILE=%~dp0MemSentryCases\\env"\r\n'
            b'"%~dp0Windows\\MemSentry.exe" %*\r\n'
        )
        checksums = {
            path.relative_to(root).as_posix(): sha256(path)
            for path in sorted(root.rglob("*")) if path.is_file()
        }
        (root / "manifest.json").write_text(
            json.dumps({"version": version, "sha256": checksums}, indent=2) + "\n",
            encoding="utf-8",
        )
        with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as zipped:
            for path in sorted(root.rglob("*")):
                add_to_zip(zipped, path, path.relative_to(root.parent))
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-bundle", type=Path, required=True)
    parser.add_argument("--windows-bundle", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "release-assets")
    args = parser.parse_args()
    try:
        print(build_portable(
            args.linux_bundle, args.windows_bundle, args.version, args.output_dir
        ))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Portable kit failed: {exc}\n")


if __name__ == "__main__":
    main()
