# MemSentry

MemSentry is a local desktop application for analysing Windows and Linux memory images with Volatility 3. It provides case management, SHA-256 integrity checks, plugin execution, optional YARA scanning, and stored artifacts using Python, PySide6, and SQLite.

## Development setup

Use Python **3.11–3.14**, Git, and a Windows or Linux desktop. Run the following commands from the repository root.

```bash
git clone https://github.com/KRakeesh04/MemSentry.git
cd MemSentry
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install runtime and development dependencies, then install the application in editable mode:

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-dev.txt
python -m pip install -e . --no-deps
```

For Ubuntu/Debian environments missing Qt system libraries:

```bash
sudo apt-get install libegl1 libgl1 libglib2.0-0
```

## Run

To prepare dependencies, build the portable application with PyInstaller, check the bundle, and launch it, run from the repository root:

```bash
python scripts/build.py --run
```

Use `python3` on Linux if `python` is unavailable. On Linux, `make run` does the same thing. Python **3.11–3.14** and internet access for the first dependency installation are required. The command creates an isolated environment in `build/venv/`; you do not need to activate it or install PyInstaller manually. Linux also needs the Qt system libraries listed above.

For development, after completing the development setup:

```bash
python -m memsentry
```

1. In **Cases**, select a writable workspace and create or open a case.
2. In **Evidence & Analysis**, register an existing memory image and verify its SHA-256.
3. In **Overview**, choose **Analyze evidence**, select the image OS, plugins, symbols root, and optional YARA rules.
4. Review plugin results, **Artifacts**, **Findings**, and **Activity**.

The workspace stores `memsentry.sqlite3` and case outputs under `cases/`. Keep source evidence separate; analysis reads the image without modifying it and checks integrity before and after processing.

Supply matching Volatility symbols under the selected root's `windows/` or `linux/` directory. Prepare symbols before offline use; plugin availability depends on the image OS and installed Volatility version. See [Volatility setup](docs/VOLATILITY_GUIDE.md) for details.

## Developer checks

```bash
python -m pytest
python -m pytest --cov=memsentry --cov-report=term-missing
python -m ruff check
python -m ruff check --fix
python -m mypy src
```

For headless Linux tests:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest
```

Use synthetic or authorised test data. Keep memory images, case output, and credentials out of commits. Follow [AGENTS.md](AGENTS.md) when changing analysis or evidence-handling code.

## Portable setup

Build on the target OS and architecture. To build without launching the GUI:

```bash
python scripts/build.py
```

The build uses the checked-in `MemSentry.spec`, generates PNG/Windows ICO assets from the application shield, and bundles Python, Qt, Volatility plugins, SQLite migrations, registry metadata, and correlation/YARA rules. It checks icon rendering, plugin discovery, database migration, and graph-page startup from outside the source tree. Existing `dist/MemSentry/` build output is replaced; keep evidence and workspaces elsewhere.

Launch the result directly on subsequent runs:

- Windows: `dist\MemSentry\MemSentry.exe`
- Linux: `./dist/MemSentry/MemSentry`

If your active environment already contains the application (editable installation), runtime dependencies, and PyInstaller, you can skip dependency installation:

```bash
python scripts/build.py --no-install
```

Copy or ZIP the **entire `dist/MemSentry/` folder**, including `_internal/`. No manual resource-copy step is needed. Python is bundled; Linux still needs the host's Qt system libraries. Select a writable workspace and supply matching symbols in the analysis dialog. Symbols, evidence, and optional acquisition tools are not downloaded or bundled by the build command. The startup check does not replace target-machine testing with an authorised test image. Windows builds must be built and validated on Windows; Linux builds on Linux.

For optional live capture, place separately obtained AVML (Linux) or WinPmem mini (Windows) in a `tools/` folder beside the executable. Add a `.env` file beside it with the applicable setting:

```dotenv
MEMSENTRY_AVML=tools/avml
MEMSENTRY_WINPMEM=tools/winpmem_mini_x64.exe
```

Packaged startup loads this file automatically; tool paths are relative to it. Existing environment variables take precedence. In development, set `MEMSENTRY_ENV_FILE` to the `.env` path or use **Load .env** in the evidence page. Live capture requires OS elevation and remains a stretch feature. No `portable.mode` marker is used.

## Build packages

Build packages on the operating system they target. The commands below start in the repository root. First build the PyInstaller folder with `python scripts/build.py`; it creates `dist/MemSentry/` and the generated application icons needed by the installers. The script prepares its own build environment unless `--no-install` is used.

### Linux: Debian package and AppImage

On Ubuntu/Debian, install the system tools and libraries:

```bash
sudo apt-get update
sudo apt-get install -y libegl1 libgl1 libglib2.0-0 curl dpkg-dev
```

Build the portable application, download AppImage tooling, and create both the `.deb` and AppImage packages:

```bash
python scripts/build.py
mkdir -p build release-assets
curl --fail --location --retry 3 \
  https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage \
  --output build/appimagetool-x86_64.AppImage
chmod +x build/appimagetool-x86_64.AppImage
python scripts/package_linux.py \
  --version "$(tr -d '[:space:]' < version.txt)" \
  --appimagetool build/appimagetool-x86_64.AppImage
```

The packages are written to `release-assets/`. This script currently builds both formats in one run. The commands above target x86-64; the packaging script also supports ARM64 when run with matching build tools and architecture. To create a portable Linux archive as well:

```bash
version="$(tr -d '[:space:]' < version.txt)"
tar -czf "release-assets/MemSentry-$version-linux-x86_64.tar.gz" -C dist MemSentry
```

### Windows: MSI installer and portable ZIP

Build on Windows with Python 3.11–3.14 and [WiX Toolset v3](https://wixtoolset.org/):

```powershell
python scripts/build.py
$version = (Get-Content version.txt -Raw).Trim()
./scripts/build_msi.ps1 -Version $version
Compress-Archive -Path dist/MemSentry `
  -DestinationPath "release-assets/MemSentry-$version-windows-x86_64.zip" `
  -CompressionLevel Optimal
```

The MSI and ZIP are written to `release-assets/`. Build Windows packages on Windows and Linux packages on Linux; the PyInstaller bundle and installers are platform-specific.

### Python source packages

To build the wheel and source archive for Python/development use (not desktop installation):

```bash
python -m pip install build
python -m build --outdir release-assets
```

### Install release packages

Tagged GitHub releases include native x86-64 packages built on their target OS:

- **Windows:** run `MemSentry-<version>-windows-x86_64.msi` and follow the setup prompts. The installer adds a Start menu shortcut and can be removed from Windows Installed Apps. Administrator permission is required for the per-machine install.
- **Debian/Ubuntu:** install `memsentry_<version>_amd64.deb` with `sudo apt install ./memsentry_<version>_amd64.deb`. Launch **MemSentry** from the application menu or run `memsentry`.
- **Other Linux distributions:** mark `MemSentry-<version>-linux-x86_64.AppImage` executable with `chmod +x` and launch it. Some distributions require FUSE support for AppImages.

Linux release packages are built on Ubuntu 22.04 x86-64. AppImages still depend on compatible host graphics/system libraries, and target-machine validation is recommended. Installers do not include memory images, Volatility symbol files, or optional acquisition tools. The Windows MSI and Linux installers are also produced by the tag-triggered [release workflow](.github/workflows/release.yml).

## Planned work

- Integrate correlation and explainable process scoring into the desktop workflow.
- Add the investigation graph and JSON/HTML report generation.
- Evaluate accuracy, repeatability, and performance with controlled Windows/Linux images.
- Validate portable distributions across supported hosts.
- Explore macOS analysis and extended live-capture support as stretch work.
- Add live correlation feature to view the memory activities (Godmode feature #60).

See [MVP requirements](docs/REQUIREMENTS.md) for the agreed scope.
