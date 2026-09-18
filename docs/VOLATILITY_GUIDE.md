# Volatility in Analysis — Developer Guide

A short, practical guide to using the Volatility boundary when adding or
extending analysis. Read this alongside `AGENTS.md` and `docs/REQUIREMENTS.md`.
Keep this guide simple and resist the urge to over-document.

## Flow

```text
AnalysisService.run(analysis_run_id, plugin_ids)
   -> PluginRunner.run_plugin(evidence_path, analysis_run_id, plugin_id, os_type)
        -> PluginRegistry   : resolve approved Volatility plugin for the OS
        -> VolatilityAdapter: execute plugin read-only, return JSON
        -> parser           : normalise rows into artifacts
        -> plugin_run repo  : record run + raw output + sha256
        -> artifact repo    : persist normalized artifacts
```

The `AnalysisService` only loops over the selected plugins and delegates to the
`PluginRunner`. Keep it that way — do not scatter direct Volatility calls
around the codebase.

Live memory capture, if implemented later, belongs in `acquisition/`, not here.
`DumpManager` produces a hashed raw file; Volatility only reads that file
afterwards, the same as a dump the investigator already selected.

## Components

| Component | Responsibility |
|-----------|----------------|
| `os_utils` | Validate/normalise `os_type` (`windows`, `linux`, `mac`) |
| `symbol_manager.SymbolManager` | Manage local ISF symbol tables |
| `adapter.VolatilityAdapter` | Boundary around Volatility 3; run plugins read-only |
| `plugin_registry.PluginRegistry` | Approved/available plugins and their parsers |
| `plugin_runner.PluginRunner` | Orchestrate one plugin run; parse and persist |
| `app.analysis_service.AnalysisService` | Orchestrate selected plugins for an evidence image |
| `correlation.engine.CorrelationEngine` | Correlate artifacts and generate forensic findings |
| `yara.YaraScanner` | Compile supplied rules, scan read-only evidence, and persist `signature_match` artifacts |

YARA is optional per analysis. Pass one or more `.yar`/`.yara` files (or a
directory containing them) to `AnalysisService.run(..., yara_rule_paths=...)`.
The scanner records SHA-256 hashes for each rule and the evidence before and
after scanning, stores raw match JSON outside the evidence file, and preserves
rule metadata plus each matched string offset. With no rule paths, the result
is `requested=False` and the analysis remains successful.

The bundled rules in `resources/yara/` are conservative triage indicators and
are not malware verdicts. YARA syntax is OS-neutral, but the indicators are
tagged for Windows, Linux, and macOS where applicable; useful detection still
depends on the strings present in the memory image.

## Initialise the pieces

Volatility needs a few collaborators wired together. Use the repository
`Database` for persistence.

```python
from memsentry.storage.database import Database
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.volatility.adapter import VolatilityAdapter
from memsentry.volatility.os_utils import normalise_os
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugin_runner import PluginRunner
from memsentry.volatility.symbol_manager import SymbolManager

database = Database("/path/to/case.db")
database.initialize()

symbol_manager = SymbolManager("/path/to/symbols")   # effect: <dir>/<os>/<table>.json
adapter = VolatilityAdapter(symbol_manager, output_dir="/path/to/dumped_files")
registry = PluginRegistry()

runner = PluginRunner(
    adapter=adapter,
    plugin_registry=registry,
    plugin_run_repository=PluginRunRepository(database),
    artifact_repository=ArtifactRepository(database),
    raw_output_dir="/path/to/raw_output",   # stored separately from evidence
)
```

## Run one plugin

```python
result = runner.run_plugin(
    evidence_path="/read/only/evidence.raw",
    analysis_run_id=analysis_run_id,   # uuid.UUID
    plugin_id="process_list",
    os_type=normalise_os("windows"),
)

print(result["plugin_run"].status)      # "completed"
print(result["raw_output_path"])        # path to saved raw JSON
print(result["artifacts"])              # persisted Artifact rows
```

`plugin_id` must be an ID from `resources/plugin_registry.json`
(`process_list`, `process_tree`, `command_line`, `network_connections`,
`loaded_modules`, `memory_injection`, `handles`, `system_info`).

On failure the runner records a `failed` plugin run and raises
`PluginRunnerError`. Callers should catch it and continue with other plugins.

## Where process/network records are stored

There are no separate `processes` or `network_connections` tables. All
normalized plugin output is persisted as rows in the single `artifacts` table,
tagged by `artifact_type` (e.g. `process`, `process_tree`, `command_line`,
`network_connection`, `handle`, `module`, `memory_region`, `system_info`).

Each artifact row stores:

- `artifact_type` and `pid` (queryable columns).
- `original_data` (JSON) containing both the raw Volatility row and a
  `normalized` sub-dict with the parser's typed fields (e.g. `process_name`,
  `ppid`, `created_at`; `protocol`, `local_address`, `local_port`,
  `remote_address`, `state`, `owner`).
- `provenance` (JSON) tracing the source plugin, row, and location.

Query the persisted records through the database layer, never raw SQLite:

```python
from memsentry.storage.repositories.artifact_repository import ArtifactRepository

repo = ArtifactRepository(database)
processes = repo.list_by_type(analysis_run_id, "process")          # Artifact rows
networks  = repo.list_by_type(analysis_run_id, "network_connection")
for row in processes:
    print(row.pid, row.original_data["normalized"]["process_name"])

all = repo.list_by_analysis_run(analysis_run_id)
```

This keeps the forensic invariants intact: the original row and its source are
preserved, and the evidence image itself is never touched.

## Use it from an AnalysisService

The service validates the selection, then runs each approved plugin:

```python
service = AnalysisService(
    volatility_adapter=adapter,
    plugin_registry=registry,
    plugin_runner=runner,
    correlation_engine=engine,   # optional
    os_type="windows",
    dump_path="/read/only/evidence.raw",
)

results = service.run(analysis_run_id, ["process_list", "network_connections"])
```

## Correlation Engine

The correlation engine processes normalized artifacts and generates forensic findings by applying detection rules.

```python
from memsentry.correlation import CorrelationEngine
from memsentry.storage.repositories.artifact_repository import ArtifactRepository

engine = CorrelationEngine(os_type="windows")
artifact_repo = ArtifactRepository(database)

# Get all artifacts for an analysis run
artifacts = artifact_repo.list_by_analysis_run(analysis_run_id)

# Run correlation analysis
result = engine.correlate(artifacts, analysis_run_id)

# Access findings
for finding in result.findings:
    print(f"Rule: {finding.rule_id}")
    print(f"Title: {finding.title}")
    print(f"Severity: {finding.severity}")
    print(f"Confidence: {finding.confidence}")

# Access relationships
for relationship in result.relationships:
    print(f"Type: {relationship.relationship_type}")
    print(f"Confidence: {relationship.confidence}")

# Access process contexts
for pid, context in result.process_contexts.items():
    print(f"PID {pid}: {context.process_name}")
    print(f"Memory regions: {len(context.memory_regions)}")
    print(f"Network connections: {len(context.network_connections)}")
```

The correlation engine implements 8 detection rules as specified in REQUIREMENTS.md:

- **MS-R001**: Executable Private Memory
- **MS-R002**: Executable Private Memory with Network Activity  
- **MS-R003**: Thread Start in Executable Private Memory
- **MS-R004**: YARA Match in Suspicious Region
- **MS-R005**: Suspicious Parent-Child Relationship
- **MS-R006**: Process with Hidden Attributes
- **MS-R007**: Multiple Suspicious Indicators in Single Process
- **MS-R008**: Unusual Network Connection Patterns

Each rule includes severity levels, confidence scores, and benign explanations to support forensic triage decisions.
```

## Safety rules (forensic invariants)

- The evidence image is opened **read-only** and never modified.
- Store raw plugin output in `raw_output_dir`, not next to the evidence.
- Record a SHA-256 of the raw output for reproducibility.
- Do not log or write secrets, evidence contents, or full memory dumps to logs.
- Do not execute arbitrary shell commands; all plugins go through the adapter.
- Handle plugin/symbol failures gracefully so one failure does not abort the rest.

## Adding a new plugin

1. Add the plugin metadata to `resources/plugin_registry.json`.
2. If it needs a parser, add one under `volatility/plugins/` and a `ParserSpec`
   entry in `plugin_runner.PARSER_SPECS`.
3. Add tests; keep `tests/` deterministic and free of real evidence.
