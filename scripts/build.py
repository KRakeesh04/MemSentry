"""One-command environment preparation, PyInstaller packaging, and startup check."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], **kwargs) -> None:
    print("+ " + subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, check=True, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-install", action="store_true",
                        help="Use the current Python environment with dependencies already installed.")
    parser.add_argument("--run", action="store_true", help="Launch the GUI after a successful build.")
    args = parser.parse_args()
    if not (3, 11) <= sys.version_info[:2] < (3, 15):
        parser.error("Use Python 3.11–3.14 to build MemSentry.")
    if sys.platform not in ("win32", "linux"):
        parser.error("Build on Windows or Linux for that target OS.")
    try:
        python = Path(sys.executable)
        if not args.no_install:
            environment = ROOT / "build" / "venv"
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            if not python.is_file():
                print(f"Creating build environment: {environment}", flush=True)
                venv.EnvBuilder(with_pip=True).create(environment)
            run([str(python), "-m", "pip", "install", "-r",
                 str(ROOT / "packaging/requirements-build.txt")])
            run([str(python), "-m", "pip", "install", "--no-deps", "-e", str(ROOT)])
        env = os.environ.copy()
        env["PYINSTALLER_CONFIG_DIR"] = str(ROOT / "build" / "pyinstaller-cache")
        run([str(python), "-m", "PyInstaller", "--noconfirm",
             "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build/pyinstaller"),
             str(ROOT / "MemSentry.spec")], cwd=ROOT, env=env)
        executable = ROOT / "dist/MemSentry" / ("MemSentry.exe" if os.name == "nt" else "MemSentry")
        smoke_env = env.copy()
        smoke_env["QT_QPA_PLATFORM"] = "offscreen"
        # An unrelated working directory catches accidental source-tree resource lookups.
        with tempfile.TemporaryDirectory(prefix="memsentry-build-check-") as folder:
            run([str(executable), "--smoke-test"], cwd=folder, env=smoke_env, timeout=120)
        print(f"Ready: {executable}\nDistribute the entire {executable.parent} folder.", flush=True)
        if args.run:
            run([str(executable)], cwd=executable.parent)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
