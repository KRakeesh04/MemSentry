# MemSentry — MVP Requirements

## 1. Purpose and Scope

MemSentry is a **portable Windows-and-Linux desktop application** for analysing *previously acquired* memory images with Volatility 3. It is a forensic triage and decision-support tool: it correlates selected memory artifacts into explainable, process-level findings and produces reproducible reports. It does not acquire live memory in the MVP (a stretch scaffold lives under `src/memsentry/acquisition/`) and it does not determine that an artifact is malware or prove attribution, criminal activity, or user intent.

The MVP implements the proposal scope with an added Linux capability. Supported inputs are Volatility-compatible Windows and Linux images (for example `.raw`, `.mem`, or supported dump formats), case metadata, and optional YARA rules. macOS investigation and nonessential export formats are stretch work only.

### 1.1 MVP workflow

```text
Create/open case → register read-only evidence → hash before analysis
→ run selected Volatility plugins → retain raw outputs → normalise artifacts
→ correlate and score → inspect findings/graph → hash after analysis
→ generate JSON and HTML reports
```

## 2. Functional Requirements

### FR-01 — Case and evidence management

The system shall:

* create and reopen a case with a case ID/name, investigator, description, and timestamps;
* register one or more memory images without automatically copying or modifying the source file;
* record evidence path, filename, size, timestamps, detected image/system information when available, and analysis history; and
* write all case data and outputs to a separate structured case directory.

### FR-02 — Integrity verification

The system shall calculate and record the SHA-256 hash of each image before analysis and again after analysis. It shall display and report a mismatch. A mismatch makes the analysis integrity status **failed**; it does not silently overwrite the original record.

### FR-03 — Volatility 3 orchestration

The system shall run a selected, documented set of Volatility 3 plugins without requiring users to enter shell commands. The MVP plugin set is:

* `windows.info`
* `windows.pslist` and `windows.pstree`
* `windows.cmdline`
* `windows.netscan`
* `windows.malfind`
* `windows.dlllist`
* `windows.threads`

For Linux images, the core MVP plugin set is:

* `linux.info`
* `linux.pslist` and `linux.pstree`
* `linux.psaux`
* `linux.netstat`
* `linux.elfs`

The interface shall select the applicable OS-specific plugin set and clearly show unavailable artifact types or rules. Linux support covers process, parent-child, command-line, network, and loaded-module artifacts. Windows-only memory-region and thread-based rules shall be marked **not applicable** for Linux unless a validated Linux equivalent is implemented and tested; they must never be reported as a negative result merely because the artifact was unavailable.

For every plugin run it shall preserve the plugin name, parameters, start/end time, duration, status, raw output location, parsed-row count, warnings/errors, and Volatility version. The user may select from this approved set. If an independent plugin fails, the system shall record the failure and continue the remaining independent plugins where possible.

### FR-04 — Artifact extraction and normalisation

The system shall transform plugin results into uniquely identified, normalised artifacts. The MVP model includes `Process`, `Thread`, `MemoryRegion`, `Module`, `NetworkConnection`, `SignatureMatch`, `Indicator`, and `EvidenceRelationship`.

Each artifact shall retain its original values and provenance: source plugin, source row/location, related process/address where available, and analysis identifier. Missing or unsupported data shall be represented as unavailable rather than invented.

### FR-05 — Optional YARA analysis

When the investigator supplies approved YARA rules, the system shall scan through the supported analysis path, retain match location and rule metadata, and create `SignatureMatch` artifacts. YARA is an MVP input, not a later feature; an analysis without rules must complete and report that YARA was not requested.

### FR-06 — Correlation, rules, and scoring

The system shall correlate artifacts using PID/PPID, thread ID, address ranges, module addresses, YARA-match locations, and network-connection ownership. It shall apply documented, deterministic, versioned rules and calculate an explainable process-level triage score.

The MVP shall implement and test **eight** correlation rules. At minimum they shall cover: executable private memory; executable private memory plus network activity; a thread start within suspicious private executable memory; a YARA match in a suspicious region; and configurable suspicious parent-child relationships. The remaining rules must be documented in the rule set before implementation.

Each finding shall include its rule identifier, score contribution, related artifacts, source evidence, severity, confidence/completeness, limitations, and possible benign explanations. Observed evidence and inferred relationships must be visibly distinguished.

### FR-07 — Investigator interface

The lightweight GUI shall allow the investigator to create/open cases, register evidence, select the approved plugins and optional YARA rules, start analysis, see stage/plugin progress, and view understandable failures.

It shall provide a dashboard and searchable/filterable process-level results. Process details shall show available identity, parent, command line, times, memory regions, threads, modules, network connections, YARA matches, rules, score, and related findings. A process/evidence graph or attack-chain view shall display relationships and label observed versus inferred edges.

### FR-08 — Reporting and persistence

The system shall persist case metadata, hashes, plugin runs, normalised artifacts, relationships, findings, rule contributions, and logs locally (SQLite plus case files is acceptable).

For a completed analysis it shall generate:

* an authoritative JSON report; and
* an investigator-readable HTML report.

Both reports shall identify the case/evidence, integrity status, selected plugins, tool and rule-set versions, successful/failed/incomplete stages, findings, supporting evidence, provenance, confidence/completeness, benign explanations, and limitations.

## 3. Non-Functional and Forensic Requirements

### NFR-01 — Read-only and safe handling

MemSentry shall open source evidence read-only, never execute extracted code, never contact discovered network endpoints, and never run arbitrary user-provided operating-system commands. It shall store outputs separately from evidence.

### NFR-02 — Provenance and repeatability

For the same input image, configuration, rule-set version, and software versions, the system shall produce consistent normalised artifacts, rule outcomes, scores, and reports (apart from run timestamps). It shall record versions, configuration, raw outputs, and errors needed to reproduce the result.

### NFR-03 — Failure visibility and responsiveness

Long-running work shall run outside the GUI thread and show progress. Missing symbols, unsupported structures, parsing failures, plugin failures, incomplete stages, and report failures shall be visible to the investigator and retained in logs/reports. Cancellation may be supported where the worker safely permits it.

### NFR-04 — Portable deployment

The MVP shall target Windows 10 or later and be packageable as a portable application for authorised USB/external storage use, with its dependencies bundled or isolated. It must not require permanent installation on the examination host. Portable packaging is subject to platform and Volatility dependency constraints, which must be documented.

### NFR-05 — Performance boundaries

The application shall avoid loading the entire image into its own memory unnecessarily, keep the interface responsive during analysis, and record processing time and parsing success for evaluation. No fixed universal processing-time target is claimed because image size, symbols, and host hardware vary.

## 4. Evaluation Acceptance Criteria

Before submission, evaluate the MVP with at least eight authorised controlled images: four benign workloads and four harmless suspicious simulations, including at least two Linux images and two Windows images. Each image shall have a ground-truth manifest. The evaluation shall record precision, recall, F1, false-positive findings per benign image, processing time, parsing success rate, hash-verification result, and repeatability, with results separated by operating-system support level.

Report clarity shall be assessed with a checklist verifying source artifacts, triggered rules, provenance, and the separation of observation from inference. Direct Volatility output and private-executable-memory-only detection are the baselines.

## 5. Explicitly Out of Scope for the MVP

The following are stretch goals and must not delay the MVP: macOS feasibility work; Linux memory-region/thread equivalence beyond the defined core Linux plugin set; live memory acquisition (package scaffold: `src/memsentry/acquisition/`; must write a raw image into the case directory, hash it, then reuse the existing evidence/analysis path — it must not call Volatility); generic plugin discovery/cataloguing; arbitrary plugin execution; CSV, PDF, GraphML, or evidence-package export; configurable scoring UI; advanced timeline visualisation; image-to-image comparison; IOC matching; and an installer.

## 6. Traceability Rule

Every finding must be traceable as:

```text
Finding → rule contribution → artifact/relationship → plugin output → analysis run
→ evidence image → SHA-256 record → case
```

This document is the MVP source of truth. The proposal defines the academic scope; the README describes the implementation and usage. Where an older README statement conflicts with this document, this MVP scope takes precedence until the README is updated.
