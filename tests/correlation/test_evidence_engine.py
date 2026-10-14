"""Synthetic forensic scenarios; no sensitive or executable evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
import yaml

from memsentry.correlation import CorrelationEngine, RuleLoadError
from memsentry.correlation.condition_evaluator import value_predicate
from memsentry.correlation.normalization import executable
from memsentry.correlation.rule_evaluator import EvaluationState
from memsentry.correlation.rule_loader import get_default_rules_path, load_rules_from_yaml
from memsentry.models.artifact import Artifact

SOURCE = "11111111-1111-4111-8111-111111111111"
TARGET = "22222222-2222-4222-8222-222222222222"
OTHER = "33333333-3333-4333-8333-333333333333"


@pytest.fixture
def scenario():
    run = uuid4()

    def artifact(kind, pid=10, **data):
        return Artifact(
            id=uuid4(),
            analysis_run_id=run,
            plugin_run_id=uuid4(),
            artifact_type=kind,
            pid=pid,
            original_data=data,
            provenance={"source": "synthetic"},
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

    return run, artifact


def rules(result):
    return {finding.rule_id for finding in result.findings}


def correlate(scenario, *artifacts):
    return CorrelationEngine().correlate(list(artifacts), scenario[0])


def memory(make, **extra):
    return make(
        "memory_region",
        **{"private": True, "protection": "PAGE_EXECUTE_READ", "start": 4096, "end": 8192, **extra},
    )


def event(make, kind, seconds=0, **extra):
    return make(
        kind,
        **{
            "process_guid": SOURCE,
            "host_id": "test-host",
            "acquisition_id": "synthetic-capture",
            "timestamp": f"2026-01-01T00:00:{seconds:02d}Z",
            "telemetry": True,
            **extra,
        },
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("PAGE_EXECUTE_READ", True),
        (0x120, True),
        ("0x04", False),
        ("r-xp", True),
        ("rw-", False),
        ("execute-ish", None),
        ("text", None),
        (None, None),
    ],
)
def test_exact_protection_normalization(value, expected):
    assert executable(value) is expected


def test_thread_must_start_in_the_same_suspicious_region(scenario):
    _, make = scenario
    bad = memory(make)
    ordinary = memory(make, start=0x3000, end=0x4000, private=False, protection="PAGE_READWRITE")
    wrong = make("thread", start_address="0x3500")
    assert "MS-R003" not in rules(correlate(scenario, bad, ordinary, wrong))
    right = make("thread", start_address="5000")
    result = correlate(scenario, bad, ordinary, right)
    index = next(i for i, f in enumerate(result.findings) if f.rule_id == "MS-R003")
    assert set(result.finding_artifact_ids[index]) == {bad.id, right.id}
    assert ordinary.id not in result.finding_artifact_ids[index]


@pytest.mark.parametrize("address", [None, "garbage", [], -1, "0x2000"])
def test_invalid_and_exclusive_addresses(scenario, address):
    _, make = scenario
    result = correlate(
        scenario, memory(make, end_inclusive=False), make("thread", start_address=address)
    )
    assert "MS-R003" not in rules(result)


@pytest.mark.parametrize(
    ("address", "space", "matched"),
    [
        (0x1500, "process_virtual", True),
        (0x3000, "process_virtual", False),
        (0x1500, "file_offset", False),
        (0x1500, "physical", False),
        (0x1500, "rva", False),
        (None, "process_virtual", False),
    ],
)
def test_yara_requires_valid_compatible_location(scenario, address, space, matched):
    _, make = scenario
    signature = make(
        "signature_match", rule="synthetic_yara", match_address=address, address_space=space
    )
    assert ("MS-R004" in rules(correlate(scenario, memory(make), signature))) is matched


@pytest.mark.parametrize(
    ("executable_value", "backing", "matched"),
    [
        (True, "UNBACKED", True),
        (False, "UNBACKED", False),
        (True, "UNKNOWN", False),
        (True, "ANONYMOUS", False),
        (True, "FILE_BACKED", False),
    ],
)
def test_module_backing_is_positive_evidence(scenario, executable_value, backing, matched):
    _, make = scenario
    module = make("module", executable=executable_value, path=None, backing=backing)
    assert ("MS-R006" in rules(correlate(scenario, module))) is matched


@pytest.mark.parametrize(
    ("parent", "child", "matched"),
    [
        ("explorer.exe", "powershell.exe", False),
        ("winword.exe", "powershell.exe", True),
        ("winword.exe", "mypowershell.exe", False),
    ],
)
def test_exact_configured_parent_child(scenario, parent, child, matched):
    _, make = scenario
    result = correlate(
        scenario,
        make("process", pid=1, process_name=parent),
        make("process", pid=2, ppid=1, process_name=child),
    )
    assert ("MS-R005" in rules(result)) is matched
    ids = {a.artifact.id for c in result.process_contexts.values() for a in c.artifacts}
    assert all(
        r.source_artifact_id in ids and r.target_artifact_id in ids for r in result.relationships
    )


@pytest.mark.parametrize(
    "split", ["host_id", "acquisition_id", "process_creation_time", "process_guid"]
)
def test_identity_separates_same_pid(scenario, split):
    _, make = scenario
    first, second = (SOURCE, OTHER) if split == "process_guid" else ("a", "b")
    if split == "process_creation_time":
        first, second = "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"
    result = correlate(
        scenario, memory(make, **{split: first}), make("network_connection", **{split: second})
    )
    assert "MS-R002" not in rules(result)
    assert len(result.process_contexts) == 2


def test_ambiguous_pid_fallback_does_not_bridge_lifetimes(scenario):
    _, make = scenario
    result = correlate(
        scenario,
        make("process", process_guid=SOURCE),
        make("process", process_guid=OTHER),
        memory(make),
        make("network_connection"),
    )
    assert "MS-R002" not in rules(result)
    assert any("Ambiguous" in warning for warning in result.warnings)


def test_cross_run_is_rejected(scenario):
    _, make = scenario
    with pytest.raises(ValueError, match="requested analysis run"):
        correlate(scenario, make("process").model_copy(update={"analysis_run_id": uuid4()}))


@pytest.mark.parametrize(
    "command",
    [
        "curl https://example.test",
        "powershell Get-Process",
        "cmd.exe /c echo ok",
        "wget file.txt",
        "/bin/bash script.sh",
    ],
)
def test_ordinary_commands_are_not_inherently_suspicious(scenario, command):
    _, make = scenario
    assert "MS-R007" not in rules(
        correlate(scenario, make("command_line", command_line=command), make("network_connection"))
    )


def test_missing_network_and_metadata_are_insufficient(scenario):
    _, make = scenario
    result = correlate(scenario, make("memory_region", protection="PAGE_EXECUTE_READ"))
    outcomes = next(iter(result.evaluations.values()))
    assert outcomes["MS-R001"].state == EvaluationState.INSUFFICIENT_EVIDENCE
    assert outcomes["MS-R002"].state == EvaluationState.INSUFFICIENT_EVIDENCE
    assert not result.findings


def test_process_view_absence_requires_complete_compatible_manifest(scenario):
    _, make = scenario
    process = make(
        "process", process_view="scan", snapshot_id="snapshot", view_process_key="pid10-created1"
    )
    manifest = make(
        "process_view",
        pid=None,
        process_view="active",
        snapshot_id="snapshot",
        process_keys=[],
        complete=True,
        compatible=True,
    )
    assert "MS-R008" in rules(correlate(scenario, process, manifest))
    incomplete = manifest.model_copy(
        update={"original_data": {**manifest.original_data, "complete": False}}
    )
    assert "MS-R008" not in rules(correlate(scenario, process, incomplete))


def clearing(make, **extra):
    return event(
        make,
        "windows_event",
        20,
        pid=None,
        provider="Microsoft-Windows-Eventlog",
        channel="Security",
        event_id=1102,
        logon_id="0x123",
        **extra,
    )


def test_log_clear_alone_does_not_invent_sequence(scenario):
    _, make = scenario
    assert "MS-R009" not in rules(correlate(scenario, clearing(make, authorized_maintenance=True)))


def test_log_clear_related_preceding_activity_and_maintenance_discount(scenario):
    _, make = scenario
    privilege = event(make, "authentication_event", 10, pid=None, event_id=4672, logon_id="0x123")
    result = correlate(scenario, clearing(make), privilege)
    assert "MS-R009" in rules(result)
    approved = correlate(scenario, clearing(make, authorized_maintenance=True), privilege)
    risk = next(d["risk_score"] for d in result.finding_details if d["rule_id"] == "MS-R009")
    assert (
        next(d["risk_score"] for d in approved.finding_details if d["rule_id"] == "MS-R009") < risk
    )
    unrelated = privilege.model_copy(
        update={"original_data": {**privilege.original_data, "logon_id": "0x456"}}
    )
    assert "MS-R009" not in rules(correlate(scenario, clearing(make), unrelated))


def access(make, **extra):
    return event(
        make,
        "process_access",
        1,
        **{
            "target_name": "lsass.exe",
            "target_process_guid": TARGET,
            "granted_access": "0x1010",
            "source_trust": "untrusted",
            **extra,
        },
    )


def test_lsass_legitimate_software_and_query_only_access(scenario):
    _, make = scenario
    assert "MS-R010" not in rules(correlate(scenario, access(make, source_trust="trusted")))
    assert "MS-R010" not in rules(correlate(scenario, access(make, granted_access="0x1000")))
    result = correlate(scenario, access(make))
    assert "MS-R010" in rules(result)
    assert "MS-R011" not in rules(result)


def test_lsass_dump_requires_supported_content_target_and_order(scenario):
    _, make = scenario
    dump = event(
        make,
        "dump_file",
        5,
        target_name="lsass.exe",
        target_process_guid=TARGET,
        dump_validated=True,
        dump_format="minidump",
    )
    assert "MS-R011" in rules(correlate(scenario, access(make), dump))
    wrong = dump.model_copy(
        update={"original_data": {**dump.original_data, "target_process_guid": OTHER}}
    )
    assert "MS-R011" not in rules(correlate(scenario, access(make), wrong))
    early = dump.model_copy(
        update={"original_data": {**dump.original_data, "timestamp": "2025-12-31T23:59:00Z"}}
    )
    assert "MS-R011" not in rules(correlate(scenario, access(make), early))
    plain = event(make, "file_creation", 5, file_path="lsass.dmp")
    assert "MS-R011" not in rules(correlate(scenario, access(make), plain))


def test_jit_is_an_observation_not_injection(scenario):
    _, make = scenario
    result = correlate(scenario, memory(make, known_benign=True))
    assert rules(result) == {"MS-R001"}
    assert result.findings[0].confidence < 0.4
    assert "JIT" in result.findings[0].description


def test_memory_only_injection_inference_and_deduplication(scenario):
    _, make = scenario
    region, thread, network = (
        memory(make),
        make("thread", start_address=0x1500),
        make("network_connection"),
    )
    result = correlate(scenario, region, thread, network, region)
    assert "MS-R012" in rules(result)
    d = next(d for d in result.finding_details if d["rule_id"] == "MS-R012")
    assert len(d["matched_artifact_ids"]) == 3
    assert d["score_contributions"]["independent_artifact_classes"] == 3
    assert "remote injection is only" in d["inferred_behavior"]


def cross_process(make):
    region = event(
        make,
        "memory_region",
        0,
        pid=20,
        process_guid=TARGET,
        private=True,
        protection="rwx",
        start=4096,
        end=8192,
    )
    remote = event(
        make,
        "remote_thread",
        3,
        target_process_guid=TARGET,
        target_pid=20,
        start_address=0x1500,
        address_space="process_virtual",
    )
    write = event(make, "process_memory_write", 2, target_process_guid=TARGET, target_pid=20)
    return region, remote, write


def test_remote_thread_injection_and_multistage_are_entity_linked(scenario):
    _, make = scenario
    region, remote, write = cross_process(make)
    network = event(make, "network_connection", 4)
    result = correlate(scenario, region, remote, write, access(make), network)
    assert {"MS-R012", "MS-R014", "MS-R018"} <= rules(result)
    assert len([f for f in result.findings if f.rule_id == "MS-R018"]) == 1
    other_network = network.model_copy(
        update={"original_data": {**network.original_data, "process_guid": OTHER}}
    )
    assert "MS-R018" not in rules(
        correlate(scenario, region, remote, write, access(make), other_network)
    )
    ordinary = remote.model_copy(
        update={"original_data": {**remote.original_data, "start_address": 0x9999}}
    )
    assert "MS-R014" not in rules(correlate(scenario, region, ordinary))


def test_image_mismatch_requires_reliable_pe_evidence(scenario):
    _, make = scenario
    comparison = make(
        "image_memory_comparison",
        comparison_method="pe_executable_sections_v1",
        comparison_reliable=True,
        unexplained_mismatch_count=12,
        relocations_accounted=True,
        loader_changes_accounted=True,
        entry_point_anomaly=True,
    )
    assert {"MS-R013", "MS-R016"} <= rules(correlate(scenario, comparison))
    explained = comparison.model_copy(
        update={"original_data": {**comparison.original_data, "unexplained_mismatch_count": 0}}
    )
    assert not ({"MS-R013", "MS-R016"} & rules(correlate(scenario, explained)))


def test_system_process_requires_path_and_real_parent(scenario):
    _, make = scenario
    process = make(
        "process",
        pid=20,
        ppid=10,
        process_name="svchost.exe",
        path="C:\\Users\\test\\svchost.exe",
        system_root="C:\\Windows",
        windows_major_version=10,
    )
    parent = make("process", process_name="cmd.exe")
    assert "MS-R015" in rules(correlate(scenario, process, parent))
    assert "MS-R015" not in rules(correlate(scenario, process))
    normal = parent.model_copy(update={"original_data": {"process_name": "services.exe"}})
    assert "MS-R015" not in rules(correlate(scenario, process, normal))


def test_protection_transition_is_observed_not_reconstructed(scenario):
    _, make = scenario
    transition = event(
        make,
        "memory_protection_transition",
        1,
        old_protection="rw-",
        new_protection="r-x",
        start=4096,
        end=8192,
    )
    thread = event(make, "thread", 2, start_address=0x1500)
    assert "MS-R017" in rules(correlate(scenario, transition, thread))
    assert "MS-R017" not in rules(
        correlate(scenario, memory(make), make("thread", start_address=0x1500))
    )


def test_raw_data_and_order_are_preserved(scenario):
    _, make = scenario
    region = memory(make)
    raw = dict(region.original_data)
    artifacts = [region, make("network_connection")]
    first, second = correlate(scenario, *artifacts), correlate(scenario, *reversed(artifacts))
    assert first.findings == second.findings
    assert first.relationships == second.relationships
    assert raw == region.original_data


def test_generic_yaml_controls_behavior_and_missing_negation(tmp_path, scenario):
    config = yaml.safe_load(get_default_rules_path().read_text())
    rule = config["rules"][0]
    rule["id"] = "MS-R099"
    rule["requires"] = {
        "all": [
            {
                "artifact_type": "memory_region",
                "as": "m",
                "where": {"field": "private", "equals": False},
            }
        ]
    }
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump({"rules": [rule]}))
    _, make = scenario
    assert "MS-R099" in rules(
        CorrelationEngine(rules_path=path).correlate([memory(make, private=False)], scenario[0])
    )
    rule["requires"] = {"not": [{"artifact_type": "network_connection", "as": "n"}]}
    path.write_text(yaml.safe_dump({"rules": [rule]}))
    result = CorrelationEngine(rules_path=path).correlate([memory(make)], scenario[0])
    assert not result.findings
    assert (
        next(iter(result.evaluations.values()))["MS-R099"].state
        == EvaluationState.INSUFFICIENT_EVIDENCE
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "cycle",
        "unknown",
        "duplicate",
        "operator",
        "severity",
        "score",
        "os",
        "artifact",
        "status",
        "window",
    ],
)
def test_invalid_configuration_is_visible(tmp_path, mutation):
    config = yaml.safe_load(get_default_rules_path().read_text())
    first = config["rules"][0]
    if mutation == "cycle":
        first["requires"] = {"rule": "MS-R002"}
    elif mutation == "unknown":
        first["requires"] = {"rule": "MS-R999"}
    elif mutation == "duplicate":
        config["rules"].append(dict(first))
    elif mutation == "operator":
        first["requires"] = {
            "artifact_type": "process",
            "as": "p",
            "where": {"field": "pid", "magical": 10},
        }
    elif mutation == "artifact":
        first["requires"] = {"artifact_type": "magic", "as": "p"}
    elif mutation == "os":
        first["applies_to"] = ["imaginary"]
    elif mutation == "status":
        first["implementation_status"] = "fake"
    elif mutation == "window":
        first["requires"] = {"left": "a", "within_seconds": "b", "seconds": -1}
    else:
        first[mutation] = "invalid"
    # Remove the auxiliary configuration because this fixture only validates its own YAML.
    config["rules"] = [r for r in config["rules"] if r["id"] != "MS-R005"]
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(config))
    with pytest.raises(RuleLoadError):
        load_rules_from_yaml(path)


def test_missing_rule_file_does_not_silently_fallback(tmp_path):
    with pytest.raises(RuleLoadError):
        CorrelationEngine(rules_path=tmp_path / "missing.yaml")


@pytest.mark.parametrize(
    ("value", "op", "expected", "result"),
    [
        (None, "not_equals", "x", None),
        (None, "exists", False, None),
        (3, "greater_than", 2, True),
        (3, "less_than", 2, False),
        ("abc", "contains_all", ["a", "c"], True),
        ("abc", "contains_any", ["z", "b"], True),
        (False, "equals", 0, False),
    ],
)
def test_predicate_semantics(value, op, expected, result):
    assert value_predicate(value, op, expected) is result


def test_failed_logon_can_correlate_by_account_without_fabricating_logon_session(scenario):
    _, make = scenario
    failed = event(
        make,
        "authentication_event",
        10,
        pid=None,
        event_id=4625,
        logon_id=0,
        user="test",
        domain="LAB",
    )
    cleared = clearing(make, user="TEST", domain="lab")
    assert "MS-R009" in rules(correlate(scenario, failed, cleared))


def test_optional_sequence_step_is_used_only_when_observed(scenario):
    _, make = scenario
    region, remote, write = cross_process(make)
    network = event(make, "network_connection", 4)
    creation = event(
        make, "process", 0, process_name="powershell.exe", command_line="powershell -enc SYNTHETIC"
    )
    result = correlate(scenario, region, remote, write, access(make), network, creation)
    detail = next(d for d in result.finding_details if d["rule_id"] == "MS-R018")
    assert str(creation.id) in detail["matched_artifact_ids"]
    out_of_order = write.model_copy(
        update={"original_data": {**write.original_data, "timestamp": "2026-01-01T00:00:05Z"}}
    )
    assert "MS-R018" not in rules(
        correlate(scenario, region, remote, out_of_order, access(make), network)
    )


def test_unknown_and_uncertain_timestamps_do_not_create_sequence(scenario):
    _, make = scenario
    dump = event(
        make,
        "dump_file",
        5,
        target_name="lsass.exe",
        target_process_guid=TARGET,
        dump_validated=True,
        dump_format="minidump",
        timestamp_uncertainty_seconds=60,
    )
    assert "MS-R011" not in rules(correlate(scenario, access(make), dump))


def test_dependency_cache_and_join_budget_are_visible(scenario):
    from memsentry.correlation.context_builder import ContextIndex
    from memsentry.correlation.normalization import normalize
    from memsentry.correlation.rule_evaluator import RuleEvaluator

    _, make = scenario
    index = ContextIndex([normalize(memory(make))])
    context = next(iter(index.contexts.values()))
    evaluator = RuleEvaluator(CorrelationEngine().rules, index, "windows")
    first = evaluator.evaluate("MS-R001", context)
    assert evaluator.evaluate("MS-R001", context) is first
    bounded = RuleEvaluator(CorrelationEngine().rules, index, "windows", max_combinations=1)
    assert bounded.evaluate("MS-R001", context).state == EvaluationState.ERROR


def test_duplicate_yaml_keys_and_unbound_aliases_are_errors(tmp_path):
    path = tmp_path / "duplicate.yaml"
    path.write_text("rules: []\nrules: []\n")
    with pytest.raises(RuleLoadError, match="Duplicate YAML key"):
        load_rules_from_yaml(path)
    base = yaml.safe_load(get_default_rules_path().read_text())["rules"][0]
    base["requires"] = {"left": "typo", "inside": "missing"}
    path.write_text(yaml.safe_dump({"rules": [base]}))
    with pytest.raises(RuleLoadError, match="Unbound"):
        load_rules_from_yaml(path)


def test_naive_creation_times_still_separate_pid_reuse(scenario):
    _, make = scenario
    result = correlate(
        scenario,
        memory(make, process_creation_time="2026-01-01 00:00:00"),
        make("network_connection", process_creation_time="2026-01-01 01:00:00"),
    )
    assert "MS-R002" not in rules(result)


def test_guid_identity_does_not_depend_on_optional_pid(scenario):
    _, make = scenario
    result = correlate(
        scenario,
        memory(make, process_guid=SOURCE),
        make("network_connection", pid=None, process_guid=SOURCE),
    )
    assert "MS-R002" in rules(result)


def test_conflicting_guid_claims_are_not_silently_merged(scenario):
    _, make = scenario
    region = memory(make, process_guid=SOURCE)
    network = make("network_connection", pid=99, process_guid=SOURCE)
    result = correlate(scenario, region, network)
    assert "MS-R002" not in rules(result)
    assert any("Conflicting lifetime" in text for text in result.warnings)


def test_parent_created_after_child_does_not_form_relationship(scenario):
    _, make = scenario
    parent = make(
        "process", pid=1, process_name="winword.exe", process_creation_time="2026-01-01T02:00:00Z"
    )
    child = make(
        "process",
        pid=2,
        ppid=1,
        process_name="powershell.exe",
        process_creation_time="2026-01-01T01:00:00Z",
    )
    result = correlate(scenario, parent, child)
    assert "MS-R005" not in rules(result)
    assert not result.relationships


def test_address_index_avoids_cartesian_thread_region_scan(scenario):
    _, make = scenario
    regions = [
        memory(make, start=i * 4096, end=(i + 1) * 4096, end_inclusive=False) for i in range(100)
    ]
    threads = [make("thread", start_address=i * 4096 + 8) for i in range(100)]
    result = CorrelationEngine(max_combinations=2000).correlate(regions + threads, scenario[0])
    assert "MS-R003" in rules(result)
    assert next(iter(result.evaluations.values()))["MS-R003"].state == EvaluationState.MATCHED


def test_same_source_record_does_not_inflate_confidence(scenario):
    from memsentry.correlation.normalization import normalize
    from memsentry.correlation.risk_scoring import score_evidence

    _, make = scenario
    region = normalize(memory(make, source_file="same.jsonl", source_record_id=1))
    thread = normalize(
        make("thread", source_file="same.jsonl", source_record_id=1, start_address=5000)
    )
    alone = score_evidence([region], 0.5, temporal=False)
    duplicate = score_evidence([region, thread], 0.5, temporal=False)
    assert alone[1] == duplicate[1]
    assert duplicate[2]["independent_artifact_classes"] == 1
