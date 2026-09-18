# MemSentry UI and Investigation Workflow Plan

## Summary

Build a native PySide6 desktop interface for loading memory images, capturing live memory, running analysis, reviewing findings, and saving investigator graph revisions. Use a consistent application shell with light/dark themes and globally visible job progress.

This design extends the documented MVP to include live acquisition and editable investigation graphs. Windows and Linux remain the primary platforms; macOS features must reflect validated capabilities. This document is a plan, not a claim that these features are implemented.

## Application layout and visual design

Use a persistent left navigation sidebar, a header showing the current case/evidence/run, a central page area, and a bottom job-status strip. Changing pages must preserve the running job, page filters, and graph draft.

| Page | Purpose and principal actions |
|---|---|
| Cases | Create/open cases; show case number, description, investigator, evidence, and recent activity. |
| Overview | Show evidence integrity, analysis coverage, findings summary, and next steps. |
| Evidence & Analysis | Load an image or capture live memory; select plugins/YARA rules; start analysis and review runs. |
| Artifacts | Search captured processes, commands, connections, modules, memory regions, threads, and YARA matches. |
| Findings | Review automated findings, supporting artifacts, rule explanations, confidence, and limitations. |
| Investigation Graph | Explore automated relationships, add manual connections/hypotheses, compare and save revisions. |
| Reports | Export JSON/HTML reports with explicit run and investigator-revision selection. |
| Activity | Inspect stage history, hash checks, plugin errors, warnings, and investigator actions. |

Put Settings and Help at the bottom of navigation. Settings cover theme, acquisition tool paths, symbol locations, and default output locations.

Use blue as the brand accent: `#2563EB` in light mode and `#60A5FA` in dark mode. Use neutral surfaces and reserve green for verified/success, amber for warnings, and red for failures. Status always includes text and an icon; color alone conveys nothing essential.

Implement shared theme tokens, spacing, typography, table styles, buttons, empty states, and validation messages. Default to the system theme, with persisted Light/Dark/System options. Use an 8-pixel spacing scale, clear keyboard focus, scalable text, accessible contrast, and labeled icon actions.

Use plain language first, with technical details available in expandable panels. A triage score must never be presented as a malware probability.

## Evidence intake, analysis, and global progress

### Start workflow

1. Create or select a case.
2. Choose **Load memory image** or **Capture live memory**.
3. Show source details, output location, target OS, and readiness checks.
4. Select available approved plugins and optional YARA rules. Offer a sensible OS-specific default selection with advanced choices expandable.
5. Review settings and start the job.

Existing images are referenced without modifying or automatically copying them. Live capture targets the current host and requires the configured tool and appropriate privileges. Show unavailable capture options with a concrete explanation.

Preflight checks include file accessibility, destination writability, tool availability, symbols, and plugin support. A successful preflight is not a guarantee that capture or analysis will succeed.

### Stages and integrity checkpoints

```text
Load image / Capture memory
            ↓
Establish SHA-256 baseline
            ↓
Extract and normalize artifacts
            ↓
Optional YARA scanning
            ↓
Correlate and persist automated findings
            ↓
Review findings and investigation graph
            ↓
Generate report when requested
```

Perform full SHA-256 checks before and after each major processing stage: extraction, requested YARA scanning, correlation, and report generation. Individual plugins display execution status within extraction; they do not introduce additional full-image hash passes.

For an existing registered image, compare against its recorded baseline. For a new image, establish the baseline before analysis. Live memory cannot have a stable pre-capture image hash: label capture as “Captured,” establish the resulting file’s baseline, and verify it before analysis.

Every checkpoint records expected/actual hashes, timestamps, evidence/run/stage identifiers, and outcome. Never replace the original baseline.

Show a green check labeled **Evidence verified** only after a completed matching hash comparison. Keep integrity status separate from stage outcome: a stage can have plugin errors while evidence integrity remains verified.

A mismatch or unreadable image blocks subsequent processing stages. Preserve available results and failure records for inspection. Independent plugin failures may continue within extraction; show incomplete coverage and affected rule applicability.

### Global job display

The status strip remains visible on every page and shows case/run, current stage, current operation, elapsed time, and measured or estimated progress. Clicking it opens a job drawer with the full stage timeline, plugin statuses, integrity checkpoints, warnings, and cancellation controls.

Use:

- Byte-based percentage for hashing.
- Clearly labeled estimated percentage/ETA for capture.
- Plugin progress when available; otherwise an indeterminate indicator.
- Stage count and current-stage progress instead of an invented overall time percentage.

Keep “Hashing…” visible while verification runs. Do not display 100% before the relevant operation finishes successfully.

Allow one active processing job per application initially; browsing completed results remains available. Support cooperative cancellation at safe boundaries, report cancellation accurately, and preserve partial-run metadata. Confirm closing the application while a job is active.

## Findings and editable investigation graph

### Artifact and finding review

Use searchable, sortable tables with shared filters and a details panel. Selecting a process opens its identity, command line, parent relationships, connections, modules, memory regions, threads, matches, and related findings.

Every finding exposes its rule, supporting artifacts, score contribution where implemented, confidence/completeness, potential benign explanations, and source provenance. Unsupported or missing artifact types appear as **Not available** or **Not applicable**, never as a clean result.

### Graph interaction

Use a native `QGraphicsView`/`QGraphicsScene` graph with selectable nodes, pan/zoom, fit-to-selection, and incremental neighborhood expansion. Provide an equivalent relationship list for keyboard use and large datasets.

Start with the selected finding or process and nearby relationships instead of rendering every artifact at once. Let users add captured artifacts from a searchable picker.

Distinguish relationships through line styles and labels:

- Observed relationships: solid, with source references.
- Automated inferred relationships: dashed, with rule/explanation.
- Investigator relationships: dotted, explicitly labeled manual.

An inspector shows provenance, relationship direction/type, explanation, and related findings. A visible legend explains the distinctions.

Manual editing supports connecting captured artifacts, creating clearly labeled hypothesis nodes, adding notes, moving nodes, hiding elements from the current view, and undo/redo. New relationships require a type and rationale. Hypotheses cannot masquerade as captured artifacts.

Use stable artifact identifiers scoped to their analysis run; PID alone is insufficient. Do not execute captured commands or contact discovered network addresses.

### Baseline and revision saving

Preserve automated findings and the initial graph as an immutable baseline. Manual work forms a separate investigation layer and does not change automated scores or source artifacts.

**Save revision** creates a named, timestamped revision associated with an investigator and baseline analysis run. Each revision stores manual nodes/relationships, annotations, hidden-element state, and layout. Previous revisions remain available.

Provide Original / Revision selection, a changes summary, and an unsaved-changes indicator. On leaving a dirty workspace, offer Save, Discard, or Cancel. Saving is transactional; a failed save preserves the draft for retry.

Manual graph saves do not trigger full memory-image hashing because they edit investigation metadata. Reports identify the exact saved revision and distinguish original findings from investigator interpretations.

## Architecture, storage, and implementation sequence

The existing repository has acquisition adapters, plugin execution, normalized artifact storage, YARA scanning, and a correlation engine. However, `AnalysisService` still has a correlation TODO, the GUI entry point is a placeholder, and migrations 001–007 do not provide relationship persistence, graph revisions, or integrity history. Report helpers in tests are not a production reporting service.

### Service and interface additions

- Use `app/bootstrap.py` to construct application configuration, repository/service factories, and the job controller. Create case-scoped dependencies when a case opens and run-scoped analysis objects when a job starts.
- Keep widgets responsible for presentation and user interaction. Expose application services for case/evidence management, job execution, graph revision saving, and reporting.
- Run analysis and hashing in a background worker process. Instantiate database connections inside the process that uses them; communicate serializable job requests and progress events back to Qt.
- Define typed job events carrying job/run ID, sequence, stage, status, completed/total units where known, message, timestamp, and optional integrity-check reference.
- Extend orchestration to invoke correlation after extraction/YARA, persist its results, and expose a run summary while preserving existing callers where practical.
- Fix correlation relationship endpoints to reference real persisted artifacts; current PID-derived UUID fallbacks cannot support reliable graph provenance.
- Persist finding-to-artifact links, rule versions, applicability/completeness, and score contributions before displaying those fields as authoritative.
- Harden acquisition integration before exposing it: prevent subprocess log-pipe stalls, support controlled termination, validate output paths, and retain failure/audit details.

### Persistence

Add migrations and repositories for:

- Job/stage history and append-only integrity checks.
- Automated artifact relationships and complete finding provenance.
- Investigation workspaces and immutable named revisions.
- Investigator annotations and manual/hypothesis graph elements.
- Audit actions and report metadata.

Store references to captured artifacts rather than duplicating evidence. Store graph revision payloads as versioned JSON with validated references, linked to an immutable baseline run. Keep artifact identities and automated relationships relationally addressable.

Record the selected configuration, tool/rule versions, and relevant hashes for reproducibility. Existing cases must continue opening after migrations. On restart, mark abandoned running jobs as interrupted/failed with a clear explanation; do not silently resume capture.

### Delivery order

1. Build the application shell, shared components, themes, navigation, and case context.
2. Implement persistence additions, worker events, stage orchestration, and integrity gates.
3. Connect existing-image intake and validated live acquisition to the global job display.
4. Deliver artifact/finding pages and the read-only automated graph.
5. Add investigator graph editing, named revisions, and revision comparison.
6. Integrate JSON/HTML reports, recovery states, and packaged Windows/Linux verification.

Treat live acquisition and investigator revisions as explicit extensions to the requirements. Include them in this plan while retaining the existing forensic invariants.

## Verification and acceptance

Use synthetic artifacts and mocked workers for routine automated testing; real acquisition runs require an authorized test environment.

Acceptance checks must demonstrate:

- Loading an existing image and simulated capture both reach persisted correlated findings.
- The global job display continues updating while users navigate.
- Every major stage has genuine pre/post hash records; mismatches block the next stage.
- Failed/skipped plugins and unavailable rules remain visible and never imply clean evidence.
- Original findings survive manual graph editing, repeated saves, reopening, and revision comparison unchanged.
- Graph links resolve to real artifacts and retain provenance; hypotheses remain visibly manual.
- Failed saves preserve drafts; cancellations and interrupted runs retain accurate history.
- JSON/HTML reports identify integrity outcomes, coverage, baseline findings, and the selected revision.
- Light/dark themes, keyboard navigation, high-DPI scaling, and large artifact lists work consistently.
- Existing schema data and current tests remain compatible; Qt integration tests cover the principal user flows.

Defaults agreed for this design: artifact and hypothesis nodes are editable in the investigator layer; saves create named revisions; full-image hash checks occur at major-stage boundaries; local investigator identity is recorded without introducing a multi-user login system.
