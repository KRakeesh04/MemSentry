# MemSentry QA Testing Guide

A practical guide for QA/testers: what is tested, how to run each test, and what
output to expect. All commands are run from the project root.

---

## 1. Prerequisites

1. Create and activate the virtual environment (see `README.md` → Installation).
2. Install development dependencies:

   ```bash
   pip install -r requirements-dev.txt
   ```

3. For dump-based tests, a memory image should exist under
   `tests/memory_dumps/`. The bundled samples are:

   | Path | OS |
   | ---- | -- |
   | `tests/memory_dumps/windows/WinDump.mem` | Windows |
   | `tests/memory_dumps/linux/LinuxDump.lime` | Linux |
   | `tests/memory_dumps/mac/MacDump.dmp` | macOS |

Use the `python` of the virtual environment (`<repo>/.venv/bin/python` or activate
the venv) when running the commands below.

---

## 2. Quick Reference

| Command | What it does | Dump required? |
| ------- | ------------ | -------------- |
| `python -m pytest` | Runs the full automated suite (~69 tests, fast, offline) | No |
| `python -m pytest -q` | Same, quiet output | No |
| `python -m pytest --cov=memsentry --cov-report=term-missing` | Suite with coverage | No |
| `python tests/correlation/test_end_to_end.py` | Correlation E2E on mock artifacts | No |
| `python tests/correlation/test_real_dump_e2e.py` | Backend pipeline E2E + real SHA-256 hashing | Yes (default: smallest Windows dump) |
| `python tests/analysis/test_memory_dump_analysis.py` | Analyse a dump, print stored DB rows | Yes (default: `sample-01.mem`) |
| `make test` / `make lint` / `make lint-fix` | Suite / lint / auto-fix lint | No |

---

## 3. Automated Tests (pytest)

All of these are fast, offline unit/integration tests. No memory dump is needed
for the subsets below (except `test_memory_dump_analysis.py`).

Run everything:

```bash
python -m pytest
```

### 3.1 Correlation engine — `tests/correlation/test_engine.py` (14 tests)

Validates `memsentry.correlation.CorrelationEngine` with rules loaded from
`resources/rules/correlation_rules.yaml`:

- engine initialization and no-artifact handling;
- process artifact correlation;
- detection rules: `MS-R001` (executable private memory), `MS-R002` (memory +
  network), `MS-R004` (YARA match), `MS-R006` (unbacked module);
- parent-child and suspicious parent-child relationships;
- OS-specific rule behavior;
- multi-indicator correlation, scoring, and finding metadata;
- YAML rule loading.

```bash
python -m pytest tests/correlation/test_engine.py -v
```

### 3.2 Models — `tests/models/test_models.py` (5 tests)

Validates the Pydantic domain models (findings, severity/confidence, and
related model constraints).

```bash
python -m pytest tests/models/test_models.py -v
```

### 3.3 Storage repositories — `tests/storage/repositories/test_repositories.py` (12 tests)

Validates the SQLite repository layer (case, evidence, analysis run, plugin run,
artifacts, findings) and CRUD/query behavior.

```bash
python -m pytest tests/storage/repositories/test_repositories.py -v
```

### 3.4 Volatility layer — `tests/volatility/` (37 tests)

| File | Covers |
| ---- | ------ |
| `test_adapter.py` (12) | `VolatilityAdapter` initialization, symbols, read-only evidence, plugin execution, JSON rendering; error paths (`VolatilitySymbolError`, unsupported OS, missing evidence). |
| `test_os_utils.py` (4) | OS normalisation (`windows`/`linux`/`mac`), validation, `supported_os_text`. |
| `test_parser_utils.py` (6) | Shared parser helpers: provenance records, required/optional PID handling and warnings. |
| `test_plugin_parsers.py` (4) | Parsers for cmdline, pstree, netscan, and malfind JSON/JSONL output, including OS-specific rejection. |
| `test_plugin_registry.py` (3) | Plugin allow-listing, OS-specific mappings, duplicate/unavailable selections. |
| `test_plugin_runner.py` (4) | `PluginRunner` completed/failed runs, artifact persistence, empty parse, unknown parser. |
| `test_pslist_parser.py` (4) | `pslist` parsing for Windows/Linux/macOS, provenance, malformed rows. |

```bash
python -m pytest tests/volatility/ -v
```

### 3.5 Memory dump analysis integration — `tests/analysis/test_memory_dump_analysis.py` (1 test)

Runs the persistence pipeline (case → evidence → analysis run → plugin run →
artifacts) against a real memory dump using a mocked Volatility adapter (the dump
is never opened or modified), then prints all stored DB rows to stdout.

```bash
python -m pytest tests/analysis/test_memory_dump_analysis.py -s
```

- Default dump: `tests/memory_dumps/windows/sample-01.mem`.
- Point at any other dump: `MEMSENTRY_TEST_DUMP=/path/to/dump`.
- Force the OS: `MEMSENTRY_TEST_OS=linux` (auto-derived from the dump's parent
  folder otherwise).
- Skipped automatically when the configured dump does not exist.

---

## 4. Correlation End-to-End Scripts

These are run as plain scripts (not pytest). They write their outputs under
`tests/correlation/test_output/` (see Section 5).

### 4.1 Mock-artifact E2E — `tests/correlation/test_end_to_end.py`

Runs the correlation engine against hand-built mock artifacts (no dump needed)
and prints findings, relationships, and process contexts.

```bash
python tests/correlation/test_end_to_end.py
```

Outputs (written directly to `tests/correlation/test_output/`):

- `correlation_summary.txt`
- `correlation_results.json`
- `findings_by_severity.txt`
- `process_risk_assessment.txt`

### 4.2 Real-dump E2E — `tests/correlation/test_real_dump_e2e.py`

Walks the whole backend against a real memory dump: initialize DB → create case →
register evidence (real SHA-256, chunked) → analysis run → simulated Volatility
plugins (`windows.info`, `pslist`, `malfind`, `netscan`, `cmdline`, YARA scan) →
correlation → store findings → generate a printable report + JSON export.

```bash
python tests/correlation/test_real_dump_e2e.py
python tests/correlation/test_real_dump_e2e.py --memory-dump tests/memory_dumps/linux/hellboy-03-sep-11-28-00.lime
```

`--memory-dump` overrides the dump; otherwise the smallest Windows dump under
`tests/memory_dumps/windows/` is used.

### Common flags

The dump-based E2E script accepts:

```bash
python tests/correlation/test_real_dump_e2e.py --help
python tests/correlation/test_real_dump_e2e.py --memory-dump tests/memory_dumps/mac/MacDump.dmp
```

The OS is inferred from the dump's parent folder name (`windows`, `linux`, or
`mac`) and drives evidence metadata, `host_os`, and the correlation engine.

### Expected successful output

A typical run ends with:

```text
Full Backend End-to-End Test Complete!
... Test Results Summary ...
  - Plugin Runs: 6
  - Artifacts Created: 11
  - Correlation Findings: 1
  - Stored Findings: 1
  - Relationships Detected: 2
```

---

## 5. Output Locations

- Automated pytest results: printed to the console.
- Correlation E2E scripts: written under `tests/correlation/test_output/`.
  The dump-based script (`test_real_dump_e2e.py`) creates a fresh **unique
  folder per run**:

  ```text
  tests/correlation/test_output/run_20260913_005754_e2544823/
  ├── test_backend.db
  └── test_output/
      ├── backend_analysis_report.txt
      └── backend_analysis_data.json
  ```

  `test_end_to_end.py` writes its four report files directly into
  `tests/correlation/test_output/`.

- `test_memory_dump_analysis.py` prints DB rows to stdout (no files).

---

## 6. Providing Custom Memory Dumps

The dump path for the correlation E2E script is set on the command line:

```bash
python tests/correlation/test_real_dump_e2e.py --memory-dump /data/images/image.raw
```

For `test_memory_dump_analysis.py` use the environment variable instead:

```bash
MEMSENTRY_TEST_DUMP=/data/images/image.raw \
MEMSENTRY_TEST_OS=windows \
python -m pytest tests/analysis/test_memory_dump_analysis.py -s
```

Forensic safety: dump files are opened read-only and are never modified by
MemSentry tests.

---

## 7. Code Quality and CI

```bash
python -m ruff check src tests      # lint
ruff check --fix                     # auto-fix
mypy src                             # static type checks
```

CI (`.github/workflows/ci.yml`) runs Ruff and pytest on Ubuntu and Windows after
merging a PR to `main`.

See `docs/` for the acceptance criteria the tests are aligned with `docs/REQUIREMENTS.md`.