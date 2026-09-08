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

## Components

| Component | Responsibility |
|-----------|----------------|
| `os_utils` | Validate/normalise `os_type` (`windows`, `linux`, `mac`) |
| `symbol_manager.SymbolManager` | Manage local ISF symbol tables |
| `adapter.VolatilityAdapter` | Boundary around Volatility 3; run plugins read-only |
| `plugin_registry.PluginRegistry` | Approved/available plugins and their parsers |
| `plugin_runner.PluginRunner` | Orchestrate one plugin run; parse and persist |
| `app.analysis_service.AnalysisService` | Orchestrate selected plugins for an evidence image |

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
