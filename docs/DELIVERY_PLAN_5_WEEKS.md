# MemSentry — Five-Week Delivery Plan

The target is the Windows-and-core-Linux MVP: Volatility correlation, eight rules, lightweight GUI, evidence integrity/provenance, and JSON/HTML reports. Freeze stretch work until the MVP has passed its controlled-image tests.

| Member | Primary responsibility | Platform responsibility |
|---|---|---|
| Rakeshan | Volatility adapter, Windows/Linux plugins, normalisation, correlation, scoring | Linux compatibility and demo validation |
| Pirasanth | SQLite schema, migrations, repositories, integrity persistence, reports, evaluation | Windows data/report validation |
| Thilaksan | PySide6 GUI, process explorer, findings/graph, release documentation | Windows GUI smoke testing |

| Week | Rakeshan | Pirasanth | Thilaksan | Exit criterion |
|---|---|---|---|---|
| 1 | Adapter/runner and OS-plugin contract | Schema, migrations, base repositories | GUI shell and navigation | One compatible image per OS and shared contracts work. |
| 2 | Windows/Linux core plugins and parsers | Evidence hashes, analysis/plugin-run and audit repositories | Case, evidence, and analysis-start workflow | Core artifacts persist and analysis progress is visible on both OSes. |
| 3 | Advanced Windows artifacts, YARA, relationships, rules 1–4 | Artifact/relationship/finding repositories | Process explorer, filters, and OS applicability | Explainable findings and provenance work end-to-end. |
| 4 | Rules 5–8, scores, graph data | JSON/HTML reports | Findings dashboard and graph/chain | Eight rules, reports, and evidence links are complete. |
| 5 | Linux demo, regression support, final rehearsal | Eight-image evaluation and metrics | Packaging, user guide, Linux/Windows smoke checks | Feature freeze, two rehearsals, release archive, and submission checklist complete. |

## Working rules

* Use a new branch for every feature, architecture change, or substantial documentation/test change. Each GitHub issue provides a preferred branch name.
* Review another member’s pull request before merge. Integrate and run a cross-platform smoke test at least twice each week.
* Linux core support is process, tree, command-line, network, and module artifacts. Linux-unavailable Windows memory/thread rules are **not applicable**, never negative findings.
* If schedule slips, protect integrity/provenance, normalisation/correlation, reports, and basic GUI before graph polish or packaging convenience.
