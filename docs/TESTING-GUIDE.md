# MemSentry QA Testing Guide

Complete the [development setup](../README.md), then run commands from the
repository root in your development environment:

```bash
python -m pip install -r requirements-dev.txt
```

Use synthetic test data. Routine acquisition tests mock tool execution and elevation;
they do not capture live memory or request administrator access.

## Select the host OS

| Host | Command | Make equivalent |
| --- | --- | --- |
| Linux | `python -m pytest --test-os=linux -q` | `make test-linux` |
| Windows | `python -m pytest --test-os=windows -q` | `make test-windows PYTHON=python` |
| macOS | `python -m pytest --test-os=macos -q` | `make test-macos` |

`python -m pytest` and `make test` detect the host automatically. Shared tests run
on every host. Tests marked `windows`, `linux`, or `macos` skip on other hosts.
The markers describe the host running the test, not the OS of the evidence image.
`--test-os` rejects a host mismatch; it cannot emulate another OS.

Windows elevation tests run on Windows. Linux elevation and native Debian
packaging tests run on Linux; the Debian test also requires `dpkg-deb`.
macOS selection is available, but macOS is not covered by CI or release builds.

## Headless GUI tests

Linux:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest --test-os=linux -q
```

Windows PowerShell (use the native Qt platform plugin):

```powershell
$env:QT_QPA_PLATFORM = "windows"
python -m pytest --test-os=windows -q
```

Linux needs the Qt system libraries listed in the README. Linux CI installs Xvfb
and wraps the Linux command with `xvfb-run -a`. Windows CI uses Qt's native
Windows platform plugin so resize and scrollbar tests exercise native geometry.

## Focused checks

```bash
python -m pytest tests/test_platform_selection.py -q
python -m pytest tests/acquisition -q
python -m pytest tests/test_portable_configuration.py tests/packaging/test_portable_kit.py -q
python -m pytest --cov=memsentry --cov-report=term-missing
python -m ruff check
python -m mypy src
```

Set `QT_QPA_PLATFORM=offscreen` for focused headless checks that create GUI
widgets. Windows geometry checks should use `QT_QPA_PLATFORM=windows`.

Portable configuration tests cover relative paths after moving the kit, workspace
and rule selection, and settings placement. Packaging tests use synthetic
application bundles, verify tool hashes, reject incomplete builds, and check that
the ZIP contains a clean workspace. They compare packaged rules with
`resources/yara/`, the single source copied into `MemSentryCases/Rules/`.

No repository `runtime/` directory is needed. Tests use temporary workspaces.
Keep real images and generated case data out of commits.

## Test areas

Use `python -m pytest <path> -v` to inspect individual test outcomes.

| Path | Coverage |
| --- | --- |
| `tests/models/` | Pydantic model validation |
| `tests/storage/repositories/` | Database persistence and repository operations |
| `tests/volatility/` | Adapter, plugin registry/runner, OS normalisation, and parsers |
| `tests/correlation/test_engine.py` | Correlation rules, relationships, and findings |
| `tests/yara/` | Scanner behavior with a fake YARA module |
| `tests/acquisition/` | Configuration, capture orchestration, elevation, hashing, and intake |
| `tests/gui/` | Qt pages, controls, and workflow interactions |
| `tests/packaging/` | Linux packages and combined portable ZIP |

Test totals change as coverage grows. A skip for another host OS is expected;
investigate failures and unexpected skips on the matching host.

## Optional dump-based integration check

```bash
python -m pytest tests/analysis/test_memory_dump_analysis.py -s
```

This test uses a mocked Volatility adapter and prints persisted database rows.
It requires an existing file at `tests/memory_dumps/windows/sample-01.mem` by
default and skips if that path is absent. It does not open the image contents or
validate real Volatility analysis. Sample images are local inputs, not bundled
release assets.

To choose an authorised image on Linux:

```bash
MEMSENTRY_TEST_DUMP=/data/images/image.raw MEMSENTRY_TEST_OS=windows \
python -m pytest tests/analysis/test_memory_dump_analysis.py -s
```

In PowerShell:

```powershell
$env:MEMSENTRY_TEST_DUMP = "D:\images\image.raw"
$env:MEMSENTRY_TEST_OS = "windows"
python -m pytest tests/analysis/test_memory_dump_analysis.py -s
```

`MEMSENTRY_TEST_OS` overrides the image OS otherwise inferred from the parent
folder name. It is independent of the pytest host selection.

## Optional correlation demonstrations

These are manually invoked scripts, not test functions executed by pytest.
They write persistent outputs under `tests/correlation/test_output/`.

```bash
python tests/correlation/test_end_to_end.py
python tests/correlation/test_real_dump_e2e.py --memory-dump /data/images/image.raw
```

The first script uses synthetic artifacts and writes `correlation_summary.txt`,
`correlation_results.json`, `findings_by_severity.txt`, and
`process_risk_assessment.txt` directly into the output directory. Repeating it
replaces those reports.

The second reads an authorised image to calculate SHA-256, but simulates plugin
results. It does not demonstrate real Volatility extraction or a real YARA scan.
Without `--memory-dump`, it selects the smallest Windows image in
`tests/memory_dumps/windows/`. It creates a unique `run_<timestamp>_<id>/` directory
containing `test_backend.db` and a `test_output/` subdirectory with
`backend_analysis_report.txt` and `backend_analysis_data.json`.

Both scripts print completion summaries. Finding counts depend on the current
rules and synthetic artifacts; do not use historical counts as acceptance criteria.
For real-image evaluation requirements, see [REQUIREMENTS.md](REQUIREMENTS.md).

## Build and release validation

`python scripts/build.py` builds for the current host and runs the packaged
`--smoke-test` from an unrelated working directory. It checks bundled resources,
plugin discovery, icons, and database migrations. This replaces existing
`dist/MemSentry/` output.

CI runs Ruff and host-specific tests on Ubuntu and Windows for pull requests and
pushes to `main`. Tag releases test both hosts before building. The portable-kit
job combines fresh Linux and Windows bundles with the checked-in acquisition
tools, verifies their hashes, and adds the configured ZIP to the release.

Linux success does not validate Windows elevation or Windows startup. Before
distribution, extract the complete kit on each supported host, launch it, and
confirm the workspace, tools, rules, and settings still resolve after moving the
whole folder. Symbols must match the target image and are not supplied by the kit.
Live acquisition requires a separate authorised test environment.
