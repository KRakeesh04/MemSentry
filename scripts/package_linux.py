"""Create Debian and AppImage packages from the PyInstaller one-folder build."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def debian_architecture(machine: str) -> str:
    """Map a supported Linux machine architecture to its Debian package name."""
    architectures = {"x86_64": "amd64", "aarch64": "arm64"}
    try:
        return architectures[machine]
    except KeyError as exc:
        raise ValueError(f"Unsupported Debian architecture: {machine}") from exc


def _copy_bundle(bundle: Path, destination: Path) -> None:
    if not bundle.is_dir() or not (bundle / "MemSentry").is_file():
        raise ValueError(f"PyInstaller bundle is missing its MemSentry executable: {bundle}")
    shutil.copytree(bundle, destination, dirs_exist_ok=True, copy_function=shutil.copy2)


def build_deb(bundle: Path, version: str, output: Path, machine: str) -> Path:
    """Assemble a Debian package that installs the self-contained app under /opt."""
    architecture = debian_architecture(machine)
    output.mkdir(parents=True, exist_ok=True)
    icon = Path("build/icons/memsentry.png")
    if not icon.is_file():
        raise FileNotFoundError(f"Application icon was not generated: {icon}")

    with tempfile.TemporaryDirectory(prefix="memsentry-deb-") as temporary:
        root = Path(temporary) / "root"
        control = root / "DEBIAN"
        app = root / "opt/memsentry"
        launcher = root / "usr/bin/memsentry"
        desktop = root / "usr/share/applications/memsentry.desktop"
        icon_target = root / "usr/share/icons/hicolor/256x256/apps/memsentry.png"
        control.mkdir(parents=True)
        launcher.parent.mkdir(parents=True)
        desktop.parent.mkdir(parents=True)
        icon_target.parent.mkdir(parents=True)
        _copy_bundle(bundle, app)

        (control / "control").write_text(
            "\n".join(
                (
                    "Package: memsentry",
                    f"Version: {version}",
                    f"Architecture: {architecture}",
                    "Maintainer: MemSentry contributors",
                    "Section: utils",
                    "Priority: optional",
                    "Depends: libegl1, libgl1, libglib2.0-0 | libglib2.0-0t64",
                    "Description: Memory forensics investigation desktop application",
                    " MemSentry analyzes memory images and correlates forensic artifacts.",
                    "",
                )
            ),
            encoding="utf-8",
        )
        launcher.write_text(
            "#!/bin/sh\nexec /opt/memsentry/MemSentry \"$@\"\n", encoding="utf-8"
        )
        launcher.chmod(0o755)
        desktop.write_text(
            "\n".join(
                (
                    "[Desktop Entry]",
                    "Type=Application",
                    "Name=MemSentry",
                    "Comment=Memory forensics investigation",
                    "Exec=memsentry",
                    "Icon=memsentry",
                    "Terminal=false",
                    "Categories=Utility;Security;",
                    "",
                )
            ),
            encoding="utf-8",
        )
        shutil.copy2(icon, icon_target)

        package = output / f"memsentry_{version}_{architecture}.deb"
        subprocess.run(
            ["dpkg-deb", "--build", "--root-owner-group", str(root), str(package)],
            check=True,
        )
    return package


def build_appimage(
    bundle: Path, version: str, output: Path, appimagetool: Path, machine: str
) -> Path:
    """Create an AppImage from the PyInstaller one-folder build."""
    architectures = {"x86_64": "x86_64", "aarch64": "aarch64"}
    if machine not in architectures:
        raise ValueError(f"Unsupported AppImage architecture: {machine}")
    if not appimagetool.is_file():
        raise FileNotFoundError(f"appimagetool executable was not found: {appimagetool}")
    icon = Path("build/icons/memsentry.png")
    if not icon.is_file():
        raise FileNotFoundError(f"Application icon was not generated: {icon}")

    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="memsentry-appimage-") as temporary:
        appdir = Path(temporary) / "MemSentry.AppDir"
        app = appdir / "usr/lib/memsentry"
        app.mkdir(parents=True)
        _copy_bundle(bundle, app)
        shutil.copy2(icon, appdir / "memsentry.png")
        (appdir / "memsentry.desktop").write_text(
            "\n".join(
                (
                    "[Desktop Entry]",
                    "Type=Application",
                    "Name=MemSentry",
                    "Comment=Memory forensics investigation",
                    "Exec=AppRun",
                    "Icon=memsentry",
                    "Terminal=false",
                    "Categories=Utility;Security;",
                    "",
                )
            ),
            encoding="utf-8",
        )
        app_run = appdir / "AppRun"
        app_run.write_text(
            "#!/bin/sh\n"
            'HERE="$(dirname "$(readlink -f "$0")")"\n'
            'exec "$HERE/usr/lib/memsentry/MemSentry" "$@"\n',
            encoding="utf-8",
        )
        app_run.chmod(0o755)

        package = output / f"MemSentry-{version}-linux-{architectures[machine]}.AppImage"
        environment = os.environ.copy()
        environment.update(
            {
                "ARCH": architectures[machine],
                "VERSION": version,
                "APPIMAGE_EXTRACT_AND_RUN": "1",
            }
        )
        subprocess.run(
            [str(appimagetool), str(appdir), str(package)],
            check=True,
            env=environment,
        )
    package.chmod(0o755)
    return package


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=Path("dist/MemSentry"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, default=Path("release-assets"))
    parser.add_argument("--appimagetool", type=Path, required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("--version must be a numeric three-part version, such as 1.2.3")

    build_deb(args.bundle, args.version, args.output, os.uname().machine)
    build_appimage(
        args.bundle,
        args.version,
        args.output,
        args.appimagetool,
        os.uname().machine,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
