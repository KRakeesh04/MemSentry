#!/usr/bin/env bash
# Creates the MemSentry five-week MVP issue plan. Run without --apply to preview.
set -Eeuo pipefail

REPO="KRakeesh04/MemSentry"
APPLY=false

usage() {
  cat <<'USAGE'
Create the MemSentry five-week MVP GitHub issue plan.

Usage:
  ./create-issues.sh [--apply] [--repo OWNER/REPO]

Options:
  --apply              Close every currently open issue in the target repository,
                       then create labels, five milestones, and a fresh issue plan.
                       Closed issues are retained by GitHub for audit/history.
  --repo OWNER/REPO    Target repository (default: KRakeesh04/MemSentry).
  -h, --help           Show this help.

Use --apply only when the repository's open issue backlog may be reset. It is
deliberately not resumable because it creates a fresh, five-week plan.
USAGE
}

while (($#)); do
  case "$1" in
    --apply) APPLY=true; shift ;;
    --repo) [[ $# -ge 2 ]] || { echo "error: --repo requires OWNER/REPO" >&2; exit 2; }; REPO="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$REPO" =~ ^[^/[:space:]]+/[^/[:space:]]+$ ]] || { echo "error: invalid repository: $REPO" >&2; exit 2; }

declare -a ISSUE_IDS=() ISSUE_NUMBERS=() TEMP_FILES=()
CREATED=0

cleanup() {
  local file
  for file in "${TEMP_FILES[@]:-}"; do [[ -z "$file" ]] || rm -f "$file"; done
}
trap cleanup EXIT

set_issue_number() { ISSUE_IDS+=("$1"); ISSUE_NUMBERS+=("$2"); }
get_issue_number() {
  local id="$1" i
  for i in "${!ISSUE_IDS[@]}"; do
    [[ "${ISSUE_IDS[$i]}" == "$id" ]] && { printf '%s' "${ISSUE_NUMBERS[$i]}"; return; }
  done
}

close_open_issues() {
  local number
  while IFS= read -r number; do
    [[ -z "$number" ]] || gh issue close "$number" --repo "$REPO" \
      --comment "Closing during the MemSentry five-week backlog reset. A replacement issue will be created by create-issues.sh." >/dev/null
  done < <(gh issue list --repo "$REPO" --state open --limit 500 --json number --jq '.[].number')
}

if $APPLY; then
  command -v gh >/dev/null 2>&1 || { echo "error: GitHub CLI (gh) is required for --apply" >&2; exit 1; }
  gh auth status >/dev/null
  gh repo view "$REPO" >/dev/null
  for user in KRakeesh04 Pirasanth-v Thilaksan8; do
    gh api "repos/$REPO/assignees/$user" >/dev/null || {
      echo "error: @$user cannot be assigned; add them as a repository collaborator first" >&2
      exit 1
    }
  done

  close_open_issues
fi

ensure_label() {
  local name="$1" color="$2" description="$3"
  if $APPLY; then gh label create "$name" --repo "$REPO" --color "$color" --description "$description" --force >/dev/null
  else printf 'LABEL     %-22s %s\n' "$name" "$description"; fi
}

ensure_milestone() {
  local title="$1" description="$2" number
  if ! $APPLY; then printf 'MILESTONE %-14s %s\n' "$title" "$description"; return; fi
  number="$(gh api "repos/$REPO/milestones?state=all&per_page=100" --jq ".[] | select(.title == \"$title\") | .number" | sed -n '1p')"
  [[ -n "$number" ]] || gh api --method POST "repos/$REPO/milestones" --field title="$title" --field description="$description" >/dev/null
}

checklist() {
  local packed="$1" item
  local -a items=()
  IFS='|' read -r -a items <<<"$packed"
  for item in "${items[@]}"; do printf -- '- [ ] %s\n' "$item"; done
}

dependencies() {
  local packed="$1" id number
  [[ -n "$packed" ]] || { printf '%s\n' '- None.'; return; }
  for id in $packed; do
    number="$(get_issue_number "$id")"
    [[ -n "$number" ]] && printf -- '- [ ] #%s (`%s`)\n' "$number" "$id" || printf -- '- [ ] `%s`\n' "$id"
  done
}

create_issue() {
  local id="$1" title="$2" assignee="$3" milestone="$4" labels="$5" estimate="$6"
  local objective="$7" guidance="$8" criteria="$9" refs="${10}" deps="${11}"
  local marker="<!-- memsentry-plan-id: $id -->" body_file url number label branch
  local -a label_args=() labels_array=()

  if ! $APPLY; then
    printf 'ISSUE     %-9s @%-12s %-12s %s\n' "$id" "$assignee" "$milestone" "$title"
    return
  fi

  case "$id" in
    PLAN-*) branch="chore/${id,,}-contracts" ;;
    VOL-*|DB-*|GUI-*|COR-*|REP-*) branch="feature/${id,,}" ;;
    TEST-*) branch="test/${id,,}" ;;
    REL-*) branch="chore/${id,,}-release" ;;
  esac

  body_file="$(mktemp)"; TEMP_FILES+=("$body_file")
  {
    printf '%s\n\n' "$marker"
    printf '## Objective\n\n%s\n\n' "$objective"
    printf '## Implementation guidance\n\n%s\n\n' "$guidance"
    printf '## Acceptance criteria\n\n'; checklist "$criteria"
    printf '\n## Dependencies\n\n'; dependencies "$deps"
    printf '\n## Delivery\n\n- **Owner:** @%s\n- **Milestone:** %s\n- **Estimate:** %s\n- **References:** %s\n' "$assignee" "$milestone" "$estimate" "$refs"
    printf '\n## Branch\n\n- [ ] Create a new branch before implementation: `%s`\n- Use a new branch for this feature, architecture change, or other non-trivial work. Do not add unrelated work to this branch.\n' "$branch"
    printf '\n## Definition of done\n\n- [ ] Focused tests pass, or the reason tests cannot run is recorded in the pull request.\n- [ ] Ruff and type checks are run for changed Python code where the environment is available.\n- [ ] Errors, unsupported artifacts, and forensic limitations are visible to the user.\n- [ ] Another team member reviews the pull request before merge.\n'
  } >"$body_file"
  IFS=',' read -r -a labels_array <<<"$labels"
  for label in "${labels_array[@]}"; do label_args+=(--label "$label"); done
  url="$(gh issue create --repo "$REPO" --title "[$id] $title" --body-file "$body_file" --assignee "$assignee" --milestone "$milestone" "${label_args[@]}")"
  rm -f "$body_file"
  number="${url##*/}"; set_issue_number "$id" "$number"; CREATED=$((CREATED + 1)); printf 'CREATED   %-9s #%s %s\n' "$id" "$number" "$url"
}

ensure_label "area:volatility" "1D76DB" "Volatility 3 adapter, plugins, and parsing"
ensure_label "area:database" "5319E7" "SQLite schema, migrations, and repositories"
ensure_label "area:gui" "A371F7" "PySide6 interface and user workflow"
ensure_label "area:correlation" "FBCA04" "Normalisation, rules, scoring, and graph"
ensure_label "area:reporting" "0075CA" "JSON/HTML reports and provenance"
ensure_label "area:testing" "0E8A16" "Controlled images, tests, and evaluation"
ensure_label "platform:linux" "BFDADC" "Linux image support or Linux validation"
ensure_label "platform:windows" "D4C5F9" "Windows image support or Windows validation"
ensure_label "priority:critical" "B60205" "Blocks downstream MVP work"
ensure_label "priority:high" "D93F0B" "Required for the MVP"
ensure_label "phase:release" "EDEDED" "Packaging, documentation, or submission"

ensure_milestone "Week 1" "Freeze contracts and establish the three delivery streams."
ensure_milestone "Week 2" "Run the first cross-platform analysis and persist its core outputs."
ensure_milestone "Week 3" "Complete normalisation and the first explainable findings."
ensure_milestone "Week 4" "Deliver the end-to-end investigation workflow."
ensure_milestone "Week 5" "Report, evaluate, package, rehearse, and submit the MVP."

create_issue "PLAN-01" "Freeze shared MVP contracts and OS/plugin matrix" "KRakeesh04" "Week 1" "area:volatility,area:database,area:gui,platform:linux,platform:windows,priority:critical" "1 day" \
  "Create the agreed contracts between the Volatility adapter, normalised artifacts, repositories, and GUI. Record exactly which Windows and Linux plugins/artifacts/rules are supported and when a rule is not applicable." \
  "Use docs/REQUIREMENTS.md as the source of truth. Agree stable IDs, JSON-like fields, plugin-run states, error representation, and the UI wording for unsupported artifacts before parallel implementation starts." \
  "OS/plugin matrix is committed|Artifact and plugin-run fields are documented|Windows-only rules are explicitly marked not applicable on Linux|All three members approve the contract" \
  "docs/REQUIREMENTS.md FR-03–FR-07; docs/DELIVERY_PLAN_5_WEEKS.md Week 1" ""

create_issue "VOL-01" "Build the Volatility runner and plugin-run record" "KRakeesh04" "Week 1" "area:volatility,priority:critical" "2 days" \
  "Implement the single adapter/runner used by the application to invoke approved Volatility plugins and retain raw output, parameters, timings, status, warnings, errors, and tool version." \
  "Do not call Volatility directly from GUI code. Use structured result objects so repositories and the GUI can consume success, failure, and incomplete states consistently. Do not use shell=True." \
  "One fake/plugin command run is captured end to end|Success and failure records contain all required fields|Raw stdout/stderr locations are retained|Focused tests cover timeout/failure parsing" \
  "AGENTS.md Volatility; REQUIREMENTS.md FR-03" "PLAN-01"

create_issue "DB-01" "Create SQLite schema, migrations, and base repositories" "Pirasanth-v" "Week 1" "area:database,priority:critical" "2 days" \
  "Implement migrations and repository interfaces for cases, evidence, hashes, analysis runs, plugin runs, artifacts, relationships, findings, and audit logs." \
  "Use the existing storage layer; do not make direct sqlite calls from other modules. Persist metadata and output references, never an entire memory image. Coordinate field names with PLAN-01." \
  "Fresh database migrates successfully|Foreign-key relationships preserve case-to-evidence-to-analysis traceability|CRUD repository tests cover normal and missing-record cases|Memory image bytes are not stored in SQLite" \
  "AGENTS.md Database; REQUIREMENTS.md FR-01, FR-02, FR-08" "PLAN-01"

create_issue "GUI-01" "Create the PySide6 application shell and navigation" "Thilaksan8" "Week 1" "area:gui,priority:critical" "1.5 days" \
  "Create a responsive GUI shell with navigation for cases, evidence, analysis, dashboard, process details, and reports. Use placeholder view models only where an upstream service is not yet available." \
  "Keep analysis work out of the GUI thread. The GUI must display actionable errors rather than tracebacks, and must not invoke Volatility or SQLite directly." \
  "Application launches|Navigation reaches each planned view|Long-task/progress interface contract is defined|GUI smoke test runs on Linux and a Windows member confirms launch" \
  "REQUIREMENTS.md FR-07; DELIVERY_PLAN_5_WEEKS.md Week 1" "PLAN-01"

create_issue "VOL-02" "Implement Windows core plugin execution and parsing" "KRakeesh04" "Week 2" "area:volatility,platform:windows,priority:critical" "2 days" \
  "Add adapter support and parsers for windows.info, pslist, pstree, cmdline, and netscan, producing shared process, command-line, and network artifacts." \
  "Run through VOL-01 only. Retain original values and source row/location. Ask Pirasanth to review persisted fields and Thilaksan to verify useful error/progress messages." \
  "A compatible Windows image produces persisted core artifacts|PID/PPID and connection ownership are retained|Missing symbols and plugin failures remain visible|Parser fixtures cover malformed/empty output" \
  "REQUIREMENTS.md FR-03–FR-04; Week 2 plan" "PLAN-01 VOL-01 DB-01"

create_issue "VOL-03" "Implement Linux core plugin execution and parsing" "KRakeesh04" "Week 2" "area:volatility,platform:linux,priority:critical" "2 days" \
  "Add support for linux.info, pslist, pstree, psaux, and netstat, mapping available data to the same shared artifacts as Windows." \
  "You are the Linux compatibility owner. Validate on a real compatible Linux image. Do not fabricate memory/thread artifacts; unsupported rules must be emitted as not applicable for the UI and reports." \
  "A compatible Linux image produces persisted process, parent-child, command-line, and network artifacts|OS-specific plugin names are selected correctly|Unsupported artifacts/rules are marked not applicable|Tests cover Linux parser mappings" \
  "REQUIREMENTS.md FR-03 Linux section; Week 2 plan" "PLAN-01 VOL-01 DB-01"

create_issue "DB-02" "Persist evidence integrity and analysis/plugin runs" "Pirasanth-v" "Week 2" "area:database,priority:high" "1.5 days" \
  "Complete repositories for SHA-256 before/after records, analysis lifecycle, plugin-run metadata, and append-only audit events." \
  "Hash the source evidence read-only and store separate before/after records. A mismatch must be visible as failed integrity status without replacing the original hash." \
  "Before/after hashes and comparison result persist|Plugin run failures can be queried with their error details|Audit events are timestamped|Repository tests cover integrity mismatch" \
  "REQUIREMENTS.md FR-02, FR-08; AGENTS.md Forensic Rules" "DB-01 VOL-01"

create_issue "GUI-02" "Implement case, evidence, and analysis-start workflow" "Thilaksan8" "Week 2" "area:gui,priority:high" "2 days" \
  "Implement the screens to create/open a case, add read-only evidence, show hashes and metadata, select approved plugins/YARA input, and start an analysis job." \
  "Use repository and service interfaces; do not access SQLite or execute Volatility in widgets. Show the selected OS and disable/inform users about inapplicable plugins." \
  "User can create a case and register evidence|Hash status is shown|Plugin selection is OS-aware|Starting an analysis shows queued/running/completed/failed progress" \
  "REQUIREMENTS.md FR-01–FR-03, FR-07" "GUI-01 DB-02 VOL-02 VOL-03"

create_issue "VOL-04" "Add advanced Windows artifacts and optional YARA path" "KRakeesh04" "Week 3" "area:volatility,platform:windows,priority:high" "2 days" \
  "Add windows.malfind, windows.dlllist, windows.threads, and the approved optional YARA analysis path, normalising regions, modules, threads, and signature matches." \
  "A run with no YARA rules must succeed and report that YARA was not requested. Preserve rule/match metadata and locations; never execute extracted content." \
  "Advanced artifacts retain source provenance|YARA requested/not-requested/failure states are distinguishable|Windows thread and region parser tests pass|Unsupported Linux equivalents remain not applicable" \
  "REQUIREMENTS.md FR-03–FR-05" "VOL-02 VOL-03 DB-01"

create_issue "COR-01" "Implement normalised relationships and rules 1–4" "KRakeesh04" "Week 3" "area:correlation,priority:high" "2 days" \
  "Implement deterministic relationship creation and the first four documented rules with score contributions and benign explanations." \
  "Use only normalised artifacts. Each result must link back to artifacts and plugin output. Rules requiring unavailable Linux data return not applicable, not a negative finding." \
  "Rules and versioned configuration are committed|Each finding contains rule ID, evidence, score contribution, and explanation|Observed/inferred relationship flag is retained|Unit tests cover positive, benign, missing, and not-applicable paths" \
  "REQUIREMENTS.md FR-06; resources/rules/correlation_rules.yaml" "VOL-04 DB-01"

create_issue "DB-03" "Persist normalised artifacts, relationships, and findings" "Pirasanth-v" "Week 3" "area:database,priority:high" "1.5 days" \
  "Finish repositories for normalised artifacts, evidence relationships, findings, rule contributions, and analysis queries used by the GUI and reports." \
  "Identifiers must support the full traceability chain. Store source references and raw/original values; use transactions for an analysis write so incomplete states are clear." \
  "Artifact-to-plugin-run and finding-to-artifact queries work|Original values and provenance survive a round trip|Failed/incomplete analysis status is queryable|Repository tests cover transaction failure" \
  "REQUIREMENTS.md FR-04, FR-06, FR-08" "DB-01 COR-01"

create_issue "GUI-03" "Build process explorer, progress, and OS applicability views" "Thilaksan8" "Week 3" "area:gui,platform:linux,platform:windows,priority:high" "2 days" \
  "Build the dashboard/process list and process-detail views using persisted data, including analysis progress, plugin failures, and OS/rule applicability." \
  "Prioritise explainability: process details should make it easy to locate command line, network, modules, regions/threads when present, score, and source evidence." \
  "Search/filter by process, PID, IP, plugin, artifact, and severity works|Progress and failed plugins are visible|Linux unavailable fields/rules read not applicable|Smoke-tested on Linux and Windows" \
  "REQUIREMENTS.md FR-07; Week 3 plan" "GUI-02 DB-03"

create_issue "COR-02" "Complete rules 5–8, scoring, and evidence graph data" "KRakeesh04" "Week 4" "area:correlation,priority:high" "2 days" \
  "Complete the eight-rule set, process-level score calculation, confidence/completeness data, and graph/attack-chain relationship output." \
  "Keep rules transparent, deterministic, versioned, and tested. Score must show individual contributions; inferred edges must never be presented as observed facts." \
  "Eight rule IDs are implemented and tested|Scores list all contributions|Graph data labels observed/inferred edges|Linux applicability is correct|Regression fixtures cover combinations of evidence" \
  "REQUIREMENTS.md FR-06; Week 4 plan" "COR-01 DB-03"

create_issue "GUI-04" "Implement findings dashboard and evidence graph/chain" "Thilaksan8" "Week 4" "area:gui,area:correlation,priority:high" "2 days" \
  "Present findings, severity, score explanations, supporting artifacts, benign explanations, and an evidence graph or attack-chain view." \
  "The visualisation must distinguish observed and inferred relationships. Prefer a readable table/list fallback if graph rendering has an error; never hide the evidence because the graph fails." \
  "Finding detail links to evidence/provenance|Observed/inferred legend is visible|Graph failure leaves findings usable|Windows and Linux data render without assuming unavailable artifacts" \
  "REQUIREMENTS.md FR-06–FR-07" "GUI-03 COR-02"

create_issue "REP-01" "Generate authoritative JSON and investigator HTML reports" "Pirasanth-v" "Week 4" "area:reporting,area:database,priority:high" "2 days" \
  "Generate reproducible JSON and readable HTML reports from persisted analysis data, including hashes, versions, configuration, statuses, findings, provenance, confidence, and limitations." \
  "JSON is the authoritative complete output. HTML is readable and must not omit plugin failures/incomplete stages. Keep reports local in the case directory." \
  "Both report formats are generated for a completed and a partially failed run|Traceability chain can be followed in JSON|HTML labels uncertainty/not-applicable data|Snapshot/content tests cover required sections" \
  "REQUIREMENTS.md FR-08; README Reporting" "DB-03 COR-02"

create_issue "TEST-01" "Create controlled-image manifests and automated evaluation" "Pirasanth-v" "Week 5" "area:testing,platform:linux,platform:windows,priority:high" "2 days" \
  "Create the authorised eight-image test set manifest and test automation: four benign and four harmless suspicious simulations, with at least two images per OS." \
  "Do not add sensitive evidence. Each manifest records source authorisation, hash, expected artifacts/findings, and known limitations. Collect precision, recall, F1, false positives, timing, parsing success, hash status, and repeatability by OS." \
  "Eight manifests meet the OS and benign/suspicious split|Automated run records all required metrics|Ground truth is reviewable|Baseline comparison is documented|No real credentials or unauthorised images are committed" \
  "REQUIREMENTS.md Evaluation Acceptance Criteria; AGENTS.md Testing" "VOL-02 VOL-03 COR-02 REP-01"

create_issue "REL-01" "Package, document, and run cross-platform release checks" "Thilaksan8" "Week 5" "phase:release,area:gui,platform:linux,platform:windows,priority:high" "1.5 days" \
  "Prepare the portable application/package instructions, update the user workflow documentation, and run clean-launch smoke tests on Linux and Windows." \
  "You and Pirasanth own Windows validation; KRakeesh04 owns Linux validation. Document platform-specific dependency or symbol limitations honestly rather than silently claiming support." \
  "Clean-copy launch succeeds on Linux and Windows|README/setup/run steps are current|Portable output locations preserve evidence read-only handling|Known limitations are documented" \
  "REQUIREMENTS.md NFR-04; Week 5 plan" "GUI-04 REP-01 TEST-01"

create_issue "REL-02" "Run final evaluation, demo rehearsal, and submission checklist" "KRakeesh04" "Week 5" "phase:release,area:testing,priority:critical" "1 day" \
  "Freeze features, triage only critical defects, rehearse the demonstration twice, and compile the final evaluation/submission evidence." \
  "All members participate: KRakeesh04 leads Linux demo, Pirasanth verifies data/report traceability, and Thilaksan verifies Windows GUI flow. No new features are added after feature freeze." \
  "Two clean demo rehearsals complete|All acceptance criteria are checked|Evaluation results and limitations are included|Release archive and final documents are ready|Critical defects are either fixed or declared" \
  "docs/DELIVERY_PLAN_5_WEEKS.md Week 5" "REL-01 TEST-01"

if $APPLY; then
  printf '\nCompleted: %d fresh issues created in %s.\n' "$CREATED" "$REPO"
else
  printf '\nPreview only. Run ./create-issues.sh --apply after gh auth login.\n'
fi
