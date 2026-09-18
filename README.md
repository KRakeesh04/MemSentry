# MemSentry

**MemSentry** is a desktop-based memory forensics platform designed to automate the analysis of previously acquired memory images using Volatility 3.

The system extracts, normalizes, correlates, and presents multiple memory artifacts as explainable process-level findings. Its purpose is to reduce the manual effort required to connect separate Volatility plugin outputs while preserving forensic integrity, provenance, repeatability, and uncertainty.

> MemSentry is a forensic triage and decision-support tool. Its findings should not be treated as conclusive proof of malware, attribution, criminal activity, or user intent.

---

## Project Overview

Volatile memory can contain evidence that may never be written to disk, including:

* active and terminated processes;
* process command lines;
* parent-child process relationships;
* network connections;
* injected or private executable memory;
* loaded modules and DLLs;
* threads and thread start addresses;
* memory-resident malware;
* YARA signature matches.

Volatility 3 can extract these artifacts through separate plugins. However, investigators usually need to manually compare and correlate multiple outputs.

MemSentry provides a correlation layer that combines selected artifacts into structured, reproducible, and investigator-readable findings.

---

## Main Objectives

The project aims to:

* integrate selected Volatility 3 plugins;
* preserve raw plugin outputs and execution details;
* normalize extracted artifacts into a consistent internal model;
* correlate related artifacts using process IDs, addresses, thread IDs, modules, and connection ownership;
* apply transparent and deterministic detection rules;
* calculate explainable process-level triage scores;
* display supporting and contradictory evidence;
* generate reproducible JSON and HTML reports;
* maintain evidence integrity and provenance throughout the analysis.

---

## Core Features

### Case Management

* Create and reopen forensic cases.
* Record case ID, investigator name, description, and timestamps.
* Maintain a structured case directory.
* Store analysis configuration and case metadata.
* Record application, Volatility, rule-set, and plugin versions.

### Evidence Handling

* Select previously acquired memory images.
* Support Volatility-compatible formats such as `.raw`, `.mem`, and supported dump formats.
* Open source evidence in read-only mode.
* Calculate SHA-256 before analysis.
* Calculate SHA-256 after analysis.
* Detect and report integrity mismatches.
* Store evidence metadata and hash records.

### Volatility 3 Integration

The initial implementation may support plugins such as:

* `windows.info`
* `windows.pslist`
* `windows.pstree`
* `windows.cmdline`
* `windows.netscan`
* `windows.malfind`
* `windows.dlllist`
* `windows.threads`

Additional plugins may be added after the minimum viable product is complete.

For every plugin execution, MemSentry records:

* plugin name;
* parameters;
* start and end times;
* duration;
* exit status;
* warnings;
* errors;
* output location;
* parsed row count;
* Volatility version.

### Artifact Normalization

Plugin outputs are converted into consistent entities such as:

* Process
* Thread
* MemoryRegion
* Module
* NetworkConnection
* SignatureMatch
* EvidenceRelationship
* Finding
* AnalysisWarning

Each artifact preserves:

* a unique identifier;
* normalized values;
* original values;
* source plugin;
* source row;
* related process or address;
* provenance information.

### Correlation and Scoring

MemSentry links artifacts using:

* process IDs;
* parent process IDs;
* thread IDs;
* memory addresses;
* module addresses;
* connection ownership;
* YARA match locations.

Example correlations include:

* private executable memory linked to a process;
* a thread starting inside a suspicious memory region;
* a process with suspicious memory and active network connections;
* a YARA match inside a suspicious memory region;
* unusual parent-child process relationships.

Each finding includes:

* triggered rules;
* rule score contributions;
* supporting evidence;
* possible benign explanations;
* confidence and completeness information;
* raw provenance;
* limitations.

### Process Explorer

The process explorer displays:

* PID;
* PPID;
* process name;
* command line;
* creation and exit times;
* executable memory regions;
* network connections;
* YARA matches;
* triggered rules;
* risk score;
* confidence status.

Investigators can search, sort, and filter process records.

### Evidence Graph

The evidence graph displays relationships between:

* parent and child processes;
* processes and threads;
* processes and memory regions;
* processes and loaded modules;
* processes and network connections;
* memory regions and YARA matches;
* findings and supporting artifacts.

Observed relationships and inferred relationships should be clearly distinguished.

### Reporting

MemSentry generates:

* an authoritative JSON report;
* an investigator-readable HTML report;
* analysis logs;
* plugin execution records;
* evidence hash records;
* normalized artifact files;
* findings and rule contributions.

Reports include:

* case metadata;
* evidence metadata;
* integrity verification;
* selected plugins;
* successful and failed stages;
* findings;
* supporting evidence;
* benign explanations;
* provenance;
* confidence and completeness;
* project limitations.

---

## Technology Stack

### Application

* Python 3.11 or Python 3.12
* PySide6
* Volatility 3
* Pydantic
* SQLite
* Jinja2
* NetworkX
* PyYAML
* `yara-python`
* `hashlib`
* `subprocess`
* Python logging

### Testing and Code Quality

* pytest
* pytest-cov
* Ruff
* mypy

### Packaging

* PyInstaller one-directory mode
* Nuitka standalone as an optional packaging comparison
* Portable ZIP distribution
* Optional Windows installer

---

## System Architecture

MemSentry uses a separate GUI and analysis worker.

```text
PySide6 GUI
    |
    | JSON job configuration
    v
Python analysis worker
    |
    ├── Volatility 3
    ├── YARA analysis
    ├── Artifact normalization
    └── Progress and error events
    |
    v
SQLite + JSONL + raw outputs
    |
    v
Correlation and scoring engine
    |
    v
JSON and HTML reports
```

The GUI and analysis worker are separated so that:

* the interface remains responsive;
* Volatility failures do not terminate the complete application;
* analysis can be cancelled;
* worker memory is released when processing finishes;
* plugin output can be streamed;
* the forensic engine can later be reused by another GUI or CLI.

---

## Project Structure

```text
memsentry/
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── src/
│   └── memsentry/
│       ├── __main__.py
│       ├── app/
│       ├── gui/
│       ├── case_management/
│       ├── evidence/
│       ├── worker/
│       ├── acquisition/
│       ├── volatility/
│       ├── models/
│       ├── normalisation/
│       ├── correlation/
│       ├── graph/
│       ├── storage/
│       ├── reporting/
│       ├── yara/
│       └── utils/
├── resources/
│   ├── rules/
│   ├── yara/
│   ├── templates/
│   ├── symbols/
│   └── icons/
├── runtime/
│   ├── cases/
│   ├── logs/
│   ├── cache/
│   └── temp/
├── tests/
├── scripts/
├── packaging/
└── docs/
```

---

## Case Directory Structure

Each investigation should use a separate case directory.

```text
CASE-2026-001/
├── case.json
├── evidence/
│   ├── evidence_manifest.json
│   ├── hash_before.json
│   └── hash_after.json
├── configuration/
│   ├── analysis_job.json
│   ├── selected_plugins.json
│   └── rule_snapshot.yaml
├── raw/
│   ├── pslist.json
│   ├── pstree.json
│   ├── netscan.json
│   ├── malfind.json
│   └── stderr/
├── normalized/
│   ├── processes.jsonl
│   ├── memory_regions.jsonl
│   ├── network_connections.jsonl
│   └── relationships.jsonl
├── database/
│   └── case.sqlite3
├── findings/
│   ├── findings.json
│   └── scoring_details.json
├── reports/
│   ├── authoritative-report.json
│   ├── investigator-report.html
│   └── graph.graphml
├── logs/
│   ├── application.log
│   ├── worker.log
│   └── audit.jsonl
└── manifest/
    ├── tool_versions.json
    ├── file_inventory.json
    └── completion_status.json
```

The original memory image should not be copied automatically. Its path, size, timestamps, and SHA-256 hash should be recorded in the evidence manifest.

---

## Installation for Development

### Requirements

* Windows 10 or later for the primary implementation
* Python 3.11 or Python 3.12
* Git
* Sufficient storage for memory images and analysis output
* A Volatility-compatible memory image for testing

### Clone the Repository

```bash
git clone https://github.com/KRakeesh04/MemSentry.git
cd memsentry
```

### Create a Virtual Environment

#### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
```

#### Linux

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

### Upgrade Packaging Tools

```bash
python -m pip install --upgrade pip setuptools wheel
```

### Install Production Dependencies

```bash
pip install -r requirements.txt
```

### Install Development Dependencies

```bash
pip install -r requirements-dev.txt
```

---

## Running the Application

Run the GUI with:

```bash
python -m memsentry
```

<!-- Run the analysis worker directly for development testing with:

```bash
python -m memsentry.worker --job path/to/analysis_job.json
```

The worker should normally be started by the GUI rather than manually. -->

---

## Running Tests

Run all tests:

```bash
pytest
```

Run tests with coverage:

```bash
pytest --cov=memsentry --cov-report=term-missing
```

Run code-quality checks:

```bash
ruff check
```

Auto-fix lint issues (same idea as running `pytest` — no extra paths needed):

```bash
ruff check --fix
```

Run static type checks:

```bash
mypy src
```

### Test: Analyse a Memory Dump and Print DB Stored Data

The integration-style test `tests/analysis/test_memory_dump_analysis.py` runs the
persistence pipeline (case, evidence, analysis run, plugin run, artifacts) against a
memory dump using a mocked Volatility adapter (fast and offline — the dump is never
opened or modified), then prints the stored DB contents to stdout.

Only run it when a memory dump is available:

```bash
pytest tests/analysis/test_memory_dump_analysis.py -s
```

It defaults to `tests/memory_dumps/windows/sample-01.mem`. Point it at any other
Windows, Linux, or macOS dump without editing the test by setting
`MEMSENTRY_TEST_DUMP`:

```bash
MEMSENTRY_TEST_DUMP=/path/to/other.dump pytest tests/analysis/test_memory_dump_analysis.py -s
```

The target OS for evidence metadata and plugin selection is derived automatically
from the dump's parent folder name (`windows`, `linux`, or `mac`). If the folder
name is not recognised, force it explicitly:

```bash
MEMSENTRY_TEST_DUMP=/path/to/other.dump MEMSENTRY_TEST_OS=linux pytest tests/analysis/test_memory_dump_analysis.py -s
```

The test is skipped automatically when the configured dump file does not exist.


### Test: Correlation End-to-End Scripts

The correlation end-to-end scripts exercise the full backend pipeline (case →
evidence → analysis run → plugin runs → artifacts → correlation → findings →
reports) against a real memory dump:

| Script | What it runs |
| ------ | ------------ |
| `tests/correlation/test_end_to_end.py` | Correlation on mock artifacts; prints findings and four reports. No dump required. |
| `tests/correlation/test_real_dump_e2e.py` | Full backend pipeline with a real dump (defaults to the smallest Windows dump), real SHA-256 hashing, printable report and JSON export. |

Run the dump-based script with:

```bash
python tests/correlation/test_real_dump_e2e.py
python tests/correlation/test_real_dump_e2e.py --memory-dump tests/memory_dumps/windows/sample-01.mem
```

The OS (`windows`, `linux`, or `mac`) is inferred from the dump's parent folder.
Each run writes its outputs to a fresh unique folder under
`tests/correlation/test_output/`:

```text
tests/correlation/test_output/run_20260913_005754_e2544823/
├── test_backend.db
└── test_output/
    ├── backend_analysis_report.txt
    └── backend_analysis_data.json
```

Run `test_end_to_end.py` (no dump) with:

```bash
python tests/correlation/test_end_to_end.py
```


| Command                                                | Purpose (one line)                                                                                                                 |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `python -m venv .venv`                                 | Creates an isolated Python virtual environment in the `.venv` folder.                                                              |
| `.venv\bin\activate`                               | Activates the virtual environment so all installed packages stay inside `.venv`.                                                   |
| `python -m pip install --upgrade pip setuptools wheel` | Updates the Python packaging tools to the latest compatible versions.                                                              |
| `pip install -r requirements-dev.txt`                  | Installs all runtime and development dependencies listed in `requirements-dev.txt` (including `requirements.txt`).                 |
| `pip install -e . --no-deps`                           | Installs your **MemSentry** project in editable mode without reinstalling dependencies, so code changes are reflected immediately. |


---

## Building the Application

The easiest way to package MemSentry as a standalone desktop application is using **PyInstaller**.

### Build the Application

Run the following command from the project root:

```bash
pyinstaller \
    --name MemSentry \
    --windowed \
    --onefile \
    --paths src \
    src/memsentry/__main__.py
```
<!-- ADD this when icon is ready -->
<!-- --add-data "resources:resources" \
--icon resources/icons/memsentry.ico \ -->

### Build Output

After the build finishes, PyInstaller creates two new folders:

```text
build/
dist/
```

The executable is located inside the **dist** folder.

```text
dist/
└── MemSentry.exe      (Windows)

or

dist/
└── MemSentry          (Linux/macOS)
```

Simply open the executable to launch the MemSentry GUI. No separate Python installation is required on the target machine.

---

## Portable Mode

MemSentry may support a portable mode for use from authorized external storage.

In portable mode:

* application files remain inside the portable directory;
* cases and logs are written to a local workspace or investigator-selected directory;
* no permanent installation is required;
* Python dependencies are bundled;
* the original evidence remains unchanged;
* administrator privileges are not required for offline image analysis.

A marker file such as the following may be used to enable portable mode:

```text
portable.mode
```

---

## Forensic Safety Principles

MemSentry must follow these principles:

* Never modify the original memory image.
* Open source evidence in read-only mode.
* Calculate SHA-256 before and after analysis.
* Store outputs in a separate case directory.
* Preserve raw plugin output.
* Record tool versions and parameters.
* Record warnings and failed analysis stages.
* Never silently ignore errors.
* Never execute extracted code.
* Never automatically contact discovered network endpoints.
* Never run arbitrary user-supplied operating-system commands.
* Never use `shell=True`.
* Restrict analysis plugins to an approved list.
* Clearly distinguish observed evidence from inferred conclusions.
* Present findings as triage indicators rather than proof of malicious activity.

---

## Initial Detection Rules

The first implementation may include rules such as:

### MS-R001 — Executable Private Memory

Detect a process containing a private executable memory region.

Possible benign explanations include:

* browser JIT compilation;
* Java runtime activity;
* .NET runtime activity;
* security software;
* legitimate unpacking or runtime code generation.

### MS-R002 — Executable Private Memory with Network Activity

Detect a process that contains private executable memory and also owns a network connection.

This correlation may be more significant than either indicator alone, but it can still occur in legitimate software.

### MS-R003 — Thread Starts in Executable Private Memory

Detect a thread whose start address falls inside a private executable memory region.

### MS-R004 — YARA Match in Suspicious Region

Detect a YARA match inside a suspicious process memory region.

### MS-R005 — Suspicious Parent-Child Relationship

Detect selected unusual process-parent relationships using a configurable rule set.

All rules must remain transparent, deterministic, versioned, and reviewable.

---

## Evaluation Plan

The tool should be evaluated using controlled and legally obtained memory images.

The minimum test dataset should include:

* benign browser activity;
* office application activity;
* Python, Java, or .NET workloads;
* controlled executable private memory;
* a controlled thread entering a test region;
* a benign injected test module;
* a controlled local network connection;
* a known YARA match.

Evaluation metrics may include:

* precision;
* recall;
* F1 score;
* false-positive findings per benign image;
* plugin execution success rate;
* parsing success rate;
* total processing time;
* peak worker memory usage;
* hash verification;
* repeatability;
* report completeness;
* investigator readability.

---

## Current Scope

The initial version focuses on:

* previously acquired memory images;
* Windows memory artifacts;
* selected Volatility 3 plugins;
* deterministic correlation rules;
* process-level triage scoring;
* evidence relationships;
* JSON and HTML reports;
* a desktop GUI;
* portable packaging.

---

## Out of Scope

The following are not part of the initial minimum viable product:

* live memory acquisition (stretch scaffold under `src/memsentry/acquisition/`; not wired into analysis yet);
* automatic malware removal;
* process termination;
* exploitation or privilege escalation;
* automatic contact with discovered IP addresses or domains;
* cloud upload of evidence;
* execution of extracted files;
* full malware attribution;
* fully autonomous AI-based classification;
* complete Windows, Linux, and macOS parity;
* replacement of Volatility 3.

Linux artifact support may be considered as a stretch goal. macOS support is considered future work or a limited feasibility study.

---

## Limitations

MemSentry results depend on:

* memory-image quality;
* successful memory acquisition;
* Volatility plugin support;
* symbol availability;
* operating-system version;
* pages remaining present in memory;
* YARA rule quality;
* project-defined rule weights;
* parser completeness.

Legitimate applications may produce behavior similar to memory injection. Browsers, Java, Python, .NET, security software, and JIT runtimes may create executable private memory.

For this reason, findings must include supporting evidence, uncertainty, possible benign explanations, and incomplete-analysis warnings.

---

## Ethical and Legal Use

MemSentry must only be used with:

* synthetic memory images;
* lawfully obtained evidence;
* explicitly authorized systems;
* controlled laboratory environments;
* approved public forensic datasets.

Do not use the tool to access, inspect, or analyze systems without authorization.

Testing should avoid:

* real third-party credentials;
* personal data where possible;
* unauthorized infrastructure;
* live malicious payloads;
* contact with external suspicious endpoints.

---

## Contribution Guidelines

Contributors should:

1. Create a separate branch.
2. Keep modules focused and testable.
3. Add tests for new functionality.
4. Preserve evidence provenance.
5. Avoid changing raw output after creation.
6. Document new rules and limitations.
7. Run Ruff, mypy, and pytest before creating a pull request.
8. Avoid committing memory images, case data, credentials, logs, or private evidence.

---

## Security Reporting

Security issues should not be posted publicly with sensitive reproduction data.

Report issues privately to the project maintainers and include:

* affected version;
* issue description;
* safe reproduction steps;
* expected behavior;
* observed behavior;
* potential impact.

Do not include real forensic evidence, passwords, access tokens, or confidential case details.

---

## Project Status

MemSentry is currently under development as a cybersecurity project.

Planned development stages include:

1. Environment setup and application scaffold.
2. Case creation and evidence hashing.
3. Volatility plugin orchestration.
4. Artifact normalization.
5. Correlation and scoring.
6. GUI implementation.
7. Evidence graph and reporting.
8. Controlled testing and evaluation.
9. Portable packaging.
10. Final documentation and demonstration.

---

## Disclaimer

MemSentry is intended for authorized digital forensic analysis, education, and research.

The system provides triage indicators and analytical support. It does not guarantee the detection of all malicious activity and should not be used as the sole basis for legal, disciplinary, or operational decisions.



---

```
memsentry/
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── LICENSE
├── .gitignore
├── memsentry.spec
│
├── src/
│   └── memsentry/
│       ├── __init__.py
│       ├── __main__.py
│       ├── version.py
│       │
│       ├── app/
│       │   ├── __init__.py
│       │   ├── bootstrap.py
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── logging_config.py
│       │
│       ├── gui/
│       │   ├── __init__.py
│       │   ├── main_window.py
│       │   ├── navigation.py
│       │   ├── dialogs/
│       │   │   ├── error_dialog.py
│       │   │   ├── startup_check_dialog.py
│       │   │   └── evidence_selector.py
│       │   ├── pages/
│       │   │   ├── dashboard_page.py
│       │   │   ├── case_setup_page.py
│       │   │   ├── analysis_page.py
│       │   │   ├── process_explorer_page.py
│       │   │   ├── findings_page.py
│       │   │   ├── evidence_graph_page.py
│       │   │   ├── reports_page.py
│       │   │   └── logs_page.py
│       │   ├── models/
│       │   │   ├── process_table_model.py
│       │   │   ├── finding_table_model.py
│       │   │   └── plugin_status_model.py
│       │   ├── widgets/
│       │   │   ├── risk_badge.py
│       │   │   ├── summary_card.py
│       │   │   ├── progress_panel.py
│       │   │   └── provenance_viewer.py
│       │   └── resources/
│       │       ├── icons/
│       │       └── styles/
│       │           └── main.qss
│       │
│       ├── case_management/
│       │   ├── __init__.py
│       │   ├── case_service.py
│       │   ├── case_manifest.py
│       │   ├── custody_log.py
│       │   └── case_paths.py
│       │
│       ├── evidence/
│       │   ├── __init__.py
│       │   ├── evidence_service.py
│       │   ├── hashing.py
│       │   ├── integrity.py
│       │   ├── file_validation.py
│       │   └── read_only_access.py
│       │
│       ├── worker/
│       │   ├── __init__.py
│       │   ├── __main__.py
│       │   ├── worker_app.py
│       │   ├── job_reader.py
│       │   ├── event_writer.py
│       │   ├── cancellation.py
│       │   └── protocol.py
│       │
│       ├── acquisition/
│       │   ├── dump_manager.py
│       │   ├── progress.py
│       │   └── adapters/
│       │       ├── windowsDumpManager.py
│       │       ├── linuxDumpManager.py
│       │       └── macDumpManager.py
│       │
│       ├── volatility/
│       │   ├── __init__.py
│       │   ├── adapter.py
│       │   ├── command_builder.py
│       │   ├── plugin_registry.py
│       │   ├── plugin_runner.py
│       │   ├── output_parser.py
│       │   ├── symbol_manager.py
│       │   └── plugins/
│       │       ├── pslist_parser.py
│       │       ├── pstree_parser.py
│       │       ├── netscan_parser.py
│       │       ├── malfind_parser.py
│       │       ├── dlllist_parser.py
│       │       └── cmdline_parser.py
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── case.py
│       │   ├── evidence.py
│       │   ├── plugin_execution.py
│       │   ├── process.py
│       │   ├── thread.py
│       │   ├── memory_region.py
│       │   ├── module.py
│       │   ├── network_connection.py
│       │   ├── signature_match.py
│       │   ├── relationship.py
│       │   ├── finding.py
│       │   └── warning.py
│       │
│       ├── normalisation/
│       │   ├── __init__.py
│       │   ├── normaliser.py
│       │   ├── identifiers.py
│       │   ├── value_conversion.py
│       │   └── provenance.py
│       │
│       ├── correlation/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   ├── indexes.py
│       │   ├── scoring.py
│       │   ├── confidence.py
│       │   ├── counter_evidence.py
│       │   └── rules/
│       │       ├── base.py
│       │       ├── executable_private_memory.py
│       │       ├── memory_network_correlation.py
│       │       └── suspicious_parent_child.py
│       │
│       ├── graph/
│       │   ├── __init__.py
│       │   ├── graph_builder.py
│       │   ├── graph_exporter.py
│       │   └── graph_serializer.py
│       │
│       ├── storage/
│       │   ├── __init__.py
│       │   ├── database.py
│       │   ├── migrations.py
│       │   ├── repositories/
│       │   │   ├── case_repository.py
│       │   │   ├── artifact_repository.py
│       │   │   ├── finding_repository.py
│       │   │   └── plugin_run_repository.py
│       │   └── schema/
│       │       └── schema.sql
│       │
│       ├── reporting/
│       │   ├── __init__.py
│       │   ├── json_report.py
│       │   ├── html_report.py
│       │   ├── report_service.py
│       │   └── redaction.py
│       │
│       ├── yara/
│       │   ├── __init__.py
│       │   ├── yara_service.py
│       │   └── rule_validator.py
│       │
│       └── utils/
│           ├── __init__.py
│           ├── datetime_utils.py
│           ├── json_utils.py
│           ├── path_utils.py
│           ├── system_info.py
│           └── version_info.py
│
├── resources/
│   ├── rules/
│   │   └── correlation_rules.yaml
│   ├── yara/
│   │   └── README.md
│   ├── templates/
│   │   ├── report.html.j2
│   │   └── report.css
│   ├── symbols/
│   │   └── README.md
│   ├── icons/
│   │   └── memsentry.ico
│   └── legal/
│       ├── LICENSES.txt
│       └── THIRD_PARTY_NOTICES.txt
│
├── runtime/
│   ├── cases/
│   │   └── .gitkeep
│   ├── logs/
│   │   └── .gitkeep
│   ├── cache/
│   │   └── .gitkeep
│   └── temp/
│       └── .gitkeep
│
├── tests/
│   ├── unit/
│   │   ├── test_hashing.py
│   │   ├── test_normalisation.py
│   │   ├── test_scoring.py
│   │   ├── test_rule_loading.py
│   │   └── test_protocol.py
│   ├── integration/
│   │   ├── test_worker_execution.py
│   │   ├── test_plugin_pipeline.py
│   │   ├── test_database.py
│   │   └── test_report_generation.py
│   ├── gui/
│   │   └── test_main_window.py
│   ├── fixtures/
│   │   ├── volatility_outputs/
│   │   ├── sample_rules/
│   │   └── manifests/
│   └── conftest.py
│
├── scripts/
│   ├── setup_windows.ps1
│   ├── setup_linux.sh
│   ├── run_gui.py
│   ├── run_worker.py
│   ├── build_windows.ps1
│   ├── build_worker.ps1
│   ├── verify_distribution.py
│   └── generate_checksums.py
│
├── packaging/
│   ├── pyinstaller/
│   │   ├── memsentry-gui.spec
│   │   ├── memsentry-worker.spec
│   │   └── hooks/
│   │       └── hook-volatility3.py
│   ├── installer/
│   │   └── memsentry.iss
│   └── portable/
│       └── portable_readme.txt
│
└── docs/
    ├── architecture.md
    ├── worker-protocol.md
    ├── packaging.md
    ├── forensic-safety.md
    ├── testing.md
    └── user-guide.md


```

### Project Structure Description

| Path | Purpose |
|------|---------|
| `pyproject.toml` | Project metadata, dependencies, and package configuration. |
| `requirements.txt` | Runtime dependencies required by the application. |
| `requirements-dev.txt` | Development tools such as pytest, Ruff and mypy. |
| `README.md` | Project documentation and setup instructions. |
| `LICENSE` | Software license. |
| `.gitignore` | Files and folders ignored by Git. |
| `memsentry.spec` | PyInstaller build configuration. |
| `src/` | Contains all application source code. |
| `src/memsentry/__main__.py` | Main entry point that launches the GUI. |
| `src/memsentry/__init__.py` | Initializes the package and stores package metadata. |
| `src/memsentry/version.py` | Stores the application version. |
| `app/` | Application startup, configuration, paths and logging. |
| `gui/` | Entire PySide6 graphical user interface. |
| `case_management/` | Handles case creation, metadata and chain-of-custody information. |
| `evidence/` | Evidence validation, hashing and integrity verification. |
| `worker/` | Background worker responsible for running analysis without freezing the GUI. |
| `acquisition/` | Stretch live-memory capture: host OS adapters, progress/ETA, write a raw dump into the case directory, then register it as evidence. Placeholders only; MVP uses an existing dump file. |
| `volatility/` | Interfaces with Volatility 3 and parses plugin outputs. |
| `models/` | Pydantic data models representing forensic artifacts. |
| `normalisation/` | Converts raw plugin outputs into standardized internal objects. |
| `correlation/` | Links related artifacts and calculates process risk scores. |
| `graph/` | Builds evidence relationship graphs for visualization and export. |
| `storage/` | SQLite database access, migrations and repositories. |
| `reporting/` | Generates JSON and HTML forensic reports. |
| `yara/` | Executes YARA scans and validates rule files. |
| `utils/` | Common helper functions shared across the project. |
| `resources/` | Static resources including icons, templates, YARA rules and configuration files. |
| `runtime/` | Runtime-generated cases, logs, cache and temporary files. |
| `tests/` | Unit, integration and GUI tests. |
| `scripts/` | Helper scripts for setup, execution, verification and packaging. |
| `packaging/` | Packaging configuration for PyInstaller, installers and portable builds. |
| `docs/` | Project documentation, architecture diagrams and user guides. |