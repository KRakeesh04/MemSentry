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

```bash
python -m memsentry
```

1. In **Cases**, select a writable workspace and create or open a case.
2. In **Evidence & Analysis**, register an existing memory image and verify its SHA-256.
3. In **Overview**, choose **Analyze evidence**, select the image OS, plugins, symbols root, and optional YARA rules.
4. Review plugin results, **Artifacts**, and **Activity**.

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

Build on the target OS using the development environment above. This recipe creates a PyInstaller directory bundle; validate it on the target machine before distribution.

Create `build/portable_entry.py` with:

```python
from memsentry.main import main

if __name__ == "__main__":
    main()
```

Run from the repository root (the command works in PowerShell and Bash):

```bash
python -m PyInstaller --noconfirm --onedir --windowed --name MemSentry --specpath build --paths src --collect-all volatility3 --copy-metadata memsentry --add-data "../src/memsentry/storage/schema:memsentry/storage/schema" --add-data "../src/memsentry/gui/assets:memsentry/gui/assets" build/portable_entry.py
```

The data paths are relative to the generated spec in `build/`. Copy the project resources beside the executable:

**Windows PowerShell:**

```powershell
Copy-Item -Recurse -Force resources dist/MemSentry/
.\dist\MemSentry\MemSentry.exe
```

**Linux:**

```bash
cp -r resources dist/MemSentry/
./dist/MemSentry/MemSentry
```

Copy or ZIP the **entire `dist/MemSentry/` folder**, including `_internal/` and `resources/`, for a compatible OS and architecture. Python is bundled; Linux still needs the host's Qt system libraries. Select a writable workspace on the portable drive and a symbols root in the analysis dialog. Confirm case creation, plugin discovery, and analysis with an authorised test image before sharing the bundle.

For optional live capture, place separately obtained AVML (Linux) or WinPmem mini (Windows) in a `tools/` folder beside the executable. Add a `.env` file beside it with the applicable setting:

```dotenv
MEMSENTRY_AVML=tools/avml
MEMSENTRY_WINPMEM=tools/winpmem_mini_x64.exe
```

Packaged startup loads this file automatically; tool paths are relative to it. Existing environment variables take precedence. In development, set `MEMSENTRY_ENV_FILE` to the `.env` path or use **Load .env** in the evidence page. Live capture requires OS elevation and remains a stretch feature. No `portable.mode` marker is used.

## Planned work

- Integrate correlation and explainable process scoring into the desktop workflow.
- Add the investigation graph and JSON/HTML report generation.
- Evaluate accuracy, repeatability, and performance with controlled Windows/Linux images.
- Validate portable distributions across supported hosts.
- Explore macOS analysis and extended live-capture support as stretch work.
- Add live correlation feature to view the memory activities (Godmode feature #60).

See [MVP requirements](docs/REQUIREMENTS.md) for the agreed scope.
