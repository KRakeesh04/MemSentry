# Live memory acquisition

MemSentry keeps acquisition separate from Volatility. The selected host adapter
runs one approved dump tool, writes a new raw image under the case directory,
calculates SHA-256, and optionally registers the image with the existing
evidence repository. Volatility reads that registered image afterward; it is
never called by an acquisition adapter.

## Supported integrations

| Host | Adapter | Tool | Configuration |
| --- | --- | --- | --- |
| Windows | `WindowsWinPmemAdapter` | WinPmem | `MEMSENTRY_WINPMEM` or `winpmem_mini_x64.exe` on `PATH` |
| Linux | `LinuxAvmlAdapter` | AVML | `MEMSENTRY_AVML` or `avml` on `PATH` |
| macOS | `MacOSPmemAdapter` | osxpmem-compatible tool | `MEMSENTRY_OSXPMEM` or `osxpmem` on `PATH` |

The executable must be installed separately, match the host architecture, and
be obtained from a trusted source. Capture requires Administrator on Windows or
root on Unix. The adapters use fixed argument layouts and `shell=False`; they
do not accept arbitrary shell commands.

## Setup and use

Install MemSentry as usual, then install the platform tool and configure its
path when it is not on `PATH`:

```bash
python -m pip install -e .
export MEMSENTRY_AVML=/trusted/tools/avml
```

For a portable package, place a `.env` file beside the executable and keep
the tools beside it, for example:

```dotenv
MEMSENTRY_AVML=tools/avml
MEMSENTRY_WINPMEM=tools/winpmem_mini_x64.exe
```

Create the manager with `DumpManager(environment_file=portable_root / ".env")`.
Paths relative to this file are resolved relative to the portable directory.
Environment variables already supplied by the operating system take priority.
Use `.env` for paths and non-secret settings only; do not store passwords,
private keys, or case data in it.

The application should create a `DumpManager` and pass a case directory. The
manager writes captures to `case/evidence/acquired/`, refuses to overwrite an
existing file, hashes the completed image, and can register it with
`EvidenceRepository` using `capture_and_register(...)`. The GUI/worker should
wrap `progress_callback(bytes_written, elapsed_seconds)` with
`ProgressTracker` from `progress.py`. It returns percentage, throughput, and
ETA details for the progress view. The GUI/worker must keep capture off the Qt
thread.

The tool's output and error are not treated as Volatility output. A failed
capture is reported, and a partial image created by the adapter is removed.
The original evidence files are never opened for writing.

## Packaging and deployment

Package the Python application and resources with the existing PyInstaller
process from the repository root. Acquisition binaries should normally remain
outside the executable so their provenance, licensing, architecture, and
administrator requirements are visible:

```bash
pyinstaller --name MemSentry --windowed --onefile --paths src src/memsentry/__main__.py
```

Deploy the trusted dump tool in a controlled `tools/` directory beside the
MemSentry executable, then set the matching `MEMSENTRY_*` variable or provide
the path through application configuration. Do not silently download dump
tools at runtime. If a tool is legally approved for bundling, it may be added
as a PyInstaller binary, but the release must still document its version,
SHA-256, license, supported OS/architecture, and required privileges.

The packaged application must run the acquisition tool on the examination host;
a Windows binary cannot capture Linux memory and vice versa. Test each packaged
build with an authorised test image, verify the recorded hash, and keep the
raw capture and tool logs in the case directory. Do not package real evidence.
