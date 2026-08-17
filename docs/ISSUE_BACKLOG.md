# MemSentry MVP Issue Backlog

This is the human-readable source for the five-week GitHub issue plan. Run `./create-issues.sh` to preview it. `./create-issues.sh --apply` closes every currently open issue in `KRakeesh04/MemSentry` (with an audit comment) and creates the fresh assigned backlog.

## Team ownership

| Member | GitHub user | Main responsibility | Platform responsibility |
|---|---|---|---|
| Rakeshan | `@KRakeesh04` | Volatility 3 adapter, Windows/Linux plugins and parsers, normalisation, rules, scoring | Owns Linux compatibility and Linux demo testing; supports Windows plugin testing |
| Pirasanth | `@Pirasanth-v` | SQLite schema, migrations, repositories, integrity persistence, reports, test manifests/evaluation | Validates database/report workflow on Windows and supports Linux review |
| Thilaksan | `@Thilaksan8` | PySide6 workflow, dashboard, process explorer, findings, graph, packaging documentation | Owns Windows GUI smoke tests; supports Linux GUI review |

All members review each other’s pull requests. Do not place direct Volatility calls in GUI code or direct SQLite calls outside repositories.

## How to use an issue

Each GitHub issue includes an objective, implementation guidance, acceptance checklist, dependencies, estimate, owner, references, and a preferred branch name. Create that branch before beginning a feature, architecture change, or substantial work. If a member is unsure what to do, read the linked requirement first, then ask in the issue before changing the agreed contract.

For Linux, unavailable memory-region/thread artifacts are **not applicable**—never “safe” or “not found.” Windows-only rules must be displayed as not applicable for Linux unless a tested equivalent exists.

## Issue map

| Week | ID | Owner | Deliverable |
|---|---|---|---|
| 1 | PLAN-01 | Rakeshan | Shared artifact, repository, GUI, and OS/plugin contracts |
| 1 | VOL-01 | Rakeshan | Single Volatility runner with raw outputs and failure records |
| 1 | DB-01 | Pirasanth | Schema, migrations, and base repositories |
| 1 | GUI-01 | Thilaksan | Application shell and navigation |
| 2 | VOL-02 | Rakeshan | Windows core plugin parsing |
| 2 | VOL-03 | Rakeshan | Linux core plugin parsing |
| 2 | DB-02 | Pirasanth | Hash, analysis, plugin-run, and audit persistence |
| 2 | GUI-02 | Thilaksan | Case, evidence, and analysis-start screens |
| 3 | VOL-04 | Rakeshan | Advanced Windows artifacts and YARA path |
| 3 | COR-01 | Rakeshan | Relationships and rules 1–4 |
| 3 | DB-03 | Pirasanth | Artifact, relationship, and finding persistence |
| 3 | GUI-03 | Thilaksan | Process explorer, progress, and OS applicability UI |
| 4 | COR-02 | Rakeshan | Rules 5–8, scores, and graph data |
| 4 | GUI-04 | Thilaksan | Findings dashboard and evidence graph/chain |
| 4 | REP-01 | Pirasanth | JSON and HTML reports |
| 5 | TEST-01 | Pirasanth | Eight-image manifests and evaluation automation |
| 5 | REL-01 | Thilaksan | Cross-platform package, documentation, and smoke checks |
| 5 | REL-02 | Rakeshan | Final evaluation, two rehearsals, and submission checklist |

## Dependency path

```text
PLAN-01
├── VOL-01 → VOL-02 / VOL-03 → VOL-04 → COR-01 → COR-02
├── DB-01 → DB-02 → DB-03 → REP-01 → TEST-01
└── GUI-01 → GUI-02 → GUI-03 → GUI-04

COR-02 + REP-01 + TEST-01 → REL-01 → REL-02
```

## Operating rules

* Rebase or merge shared contracts before starting dependent work.
* Run a Linux and Windows smoke check every week once the relevant workflow exists.
* Preserve evidence read-only; record SHA-256 before and after analysis.
* Keep raw plugin output, configuration, versions, warnings, and failures so every finding is traceable.
* Feature-freeze at the end of Week 5. During the final days, allow only critical fixes, reports, documentation, and rehearsal work.
