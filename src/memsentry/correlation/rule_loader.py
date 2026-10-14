"""Strict, observable rule loading; no implicit fallback detection behavior."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from memsentry.correlation.condition_evaluator import RELATION_OPS, VALUE_OPS
from memsentry.correlation.normalization import ARTIFACT_TYPES
from memsentry.models.finding import FindingSeverity


@dataclass(frozen=True, slots=True)
class CorrelationRule:
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    base_score: float
    applicable_os: tuple[str, ...] = ("windows", "linux", "mac")
    required_artifacts: tuple[str, ...] = ()
    benign_explanations: tuple[str, ...] = ()
    requires: dict[str, Any] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    mitre_attack: tuple[str, ...] = ()
    implementation_status: str = "implemented"
    relationships: tuple[dict[str, Any], ...] = ()


class RuleLoadError(RuntimeError):
    """Invalid rules must stop correlation rather than silently change its meaning."""


class _UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise RuleLoadError(f"Duplicate YAML key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _validate_bindings(
    node: dict[str, Any], available: set[str], rules: dict[str, CorrelationRule]
) -> set[str]:
    """Validate dataflow after the dependency DAG has been checked for cycles."""
    available = set(available)
    if "rule" in node:
        return _validate_bindings(rules[node["rule"]].requires, available, rules)
    if "artifact_type" in node:
        return available | {node.get("as", node["artifact_type"])}
    if "optional" in node:
        return _validate_bindings(node["optional"], available, rules)
    if "sequence" in node:
        references = {step["binding"] for step in node["sequence"]["steps"]}
        if references - available:
            raise RuleLoadError(f"Unbound sequence artifacts: {sorted(references - available)}")
    if "left" in node:
        op = next(key for key in node if key in RELATION_OPS)
        references = {node["left"], node[op]}
        if references - available:
            raise RuleLoadError(f"Unbound relationship artifacts: {sorted(references - available)}")
    for child in node.get("all", []):
        available = _validate_bindings(child, available, rules)
    branches = [_validate_bindings(child, available, rules) for child in node.get("any", [])]
    for branch in branches:
        available |= branch
    for child in node.get("not", []):
        _validate_bindings(child, available, rules)
    return available


def _expression(node: Any, *, predicate: bool = False) -> set[str]:
    if not isinstance(node, dict) or not node:
        raise RuleLoadError("Conditions must be nonempty mappings")
    dependencies: set[str] = set()
    if "optional" in node and not predicate:
        if set(node) != {"optional"}:
            raise RuleLoadError("optional accepts one expression")
        return _expression(node["optional"])
    if "sequence" in node and not predicate:
        sequence = node["sequence"]
        if (
            set(node) != {"sequence"}
            or not isinstance(sequence, dict)
            or set(sequence) != {"steps", "seconds", "entity"}
        ):
            raise RuleLoadError("sequence requires steps, seconds and entity")
        if sequence["entity"] not in {
            "same_process_instance",
            "same_source_process",
            "same_target_process",
            "same_logon_id",
        }:
            raise RuleLoadError("Temporal sequences require an explicit entity relationship")
        steps = sequence["steps"]
        if not isinstance(steps, list) or len(steps) < 2:
            raise RuleLoadError("sequence requires at least two steps")
        for step in steps:
            if (
                not isinstance(step, dict)
                or set(step) - {"binding", "optional"}
                or not isinstance(step.get("binding"), str)
                or not isinstance(step.get("optional", False), bool)
            ):
                raise RuleLoadError("Invalid sequence step")
        if sum(not step.get("optional", False) for step in steps) < 2:
            raise RuleLoadError("sequence requires at least two mandatory steps")
        _expression({"left": "first", "within_seconds": "last", "seconds": sequence["seconds"]})
        return set()
    bool_keys = set(node) & {"all", "any", "not"}
    if bool_keys:
        if set(node) != bool_keys:
            raise RuleLoadError("Boolean groups cannot mix selectors and predicates")
        for key in sorted(bool_keys):
            if not isinstance(node[key], list):
                raise RuleLoadError(f"{key} requires a list")
            for child in node[key]:
                dependencies |= _expression(child, predicate=predicate)
        return dependencies
    if "rule" in node and not predicate:
        if set(node) != {"rule"} or not isinstance(node["rule"], str):
            raise RuleLoadError("Invalid dependency")
        return {node["rule"]}
    if "artifact_type" in node and not predicate:
        if node["artifact_type"] not in ARTIFACT_TYPES:
            raise RuleLoadError(f"Unknown artifact type: {node['artifact_type']}")
        if "as" not in node:
            # Compatibility with simple legacy YAML predicates (conditions now execute).
            if "field" in node:
                _expression({k: v for k, v in node.items() if k != "artifact_type"}, predicate=True)
                return set()
            raise RuleLoadError("Artifact selector requires an 'as' binding")
        if set(node) - {"artifact_type", "as", "where", "scope"}:
            raise RuleLoadError("Unknown selector keys")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", str(node["as"])):
            raise RuleLoadError("Invalid artifact binding")
        if node.get("scope", "process") not in {"process", "global"}:
            raise RuleLoadError("Invalid selector scope")
        if "where" in node:
            _expression(node["where"], predicate=True)
        return set()
    if "field" in node and predicate:
        ops = set(node) & VALUE_OPS
        if len(ops) != 1 or set(node) != {"field", *ops} or not isinstance(node["field"], str):
            raise RuleLoadError("Field predicate requires exactly one supported operator")
        op = next(iter(ops))
        value = node[op]
        if op in {"one_of", "contains_any", "contains_all"} and not isinstance(value, list):
            raise RuleLoadError(f"{op} requires a list")
        if op == "exists" and not isinstance(value, bool):
            raise RuleLoadError("exists requires a boolean")
        if op in {"greater_than", "less_than"} and (
            not isinstance(value, (int, float)) or isinstance(value, bool)
        ):
            raise RuleLoadError(f"{op} requires a number")
        if op == "matches_regex":
            try:
                re.compile(value)
            except (re.error, TypeError) as exc:
                raise RuleLoadError(f"Invalid command pattern: {exc}") from exc
        return set()
    if "left" in node and not predicate:
        ops = set(node) & RELATION_OPS
        if len(ops) != 1 or set(node) - {"left", "field", "seconds", *ops}:
            raise RuleLoadError("Relation requires exactly one supported operator")
        op = next(iter(ops))
        if not isinstance(node["left"], str) or not isinstance(node[op], str):
            raise RuleLoadError("Relations must reference artifact bindings")
        if op == "within_seconds":
            if (
                not isinstance(node.get("seconds"), (int, float))
                or isinstance(node["seconds"], bool)
                or not 0 <= node["seconds"] <= 604800
            ):
                raise RuleLoadError("Temporal window must be 0..604800 seconds")
        elif "seconds" in node:
            raise RuleLoadError("seconds is only valid for within_seconds")
        return set()
    raise RuleLoadError(f"Unsupported condition: {node}")


def load_rules_from_yaml(
    rule_file_path: str | Path, os_type: str = "windows"
) -> list[CorrelationRule]:
    if os_type not in {"windows", "linux", "mac"}:
        raise RuleLoadError(f"Unsupported OS: {os_type}")
    path = Path(rule_file_path)
    try:
        config = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
        if not isinstance(config, dict) or not isinstance(config.get("rules"), list):
            raise RuleLoadError("Configuration requires a rules list")
        rules: dict[str, CorrelationRule] = {}
        dependencies: dict[str, set[str]] = {}
        for item in config["rules"]:
            if not isinstance(item, dict):
                raise RuleLoadError("Each rule must be a mapping")
            rid = item.get("id", "")
            if not re.fullmatch(r"MS-R\d{3}", rid) or rid in rules:
                raise RuleLoadError(f"Invalid or duplicate rule ID: {rid}")
            allowed = {
                "id",
                "name",
                "description",
                "severity",
                "score",
                "applies_to",
                "requires",
                "implementation_status",
                "benign_explanations",
                "limitations",
                "mitre_attack",
                "relationships",
                "configuration",
                "group_by",
            }
            if set(item) - allowed:
                raise RuleLoadError(f"{rid}: unknown configuration keys {set(item) - allowed}")
            for key in ("name", "description"):
                if not isinstance(item.get(key), str) or not item[key]:
                    raise RuleLoadError(f"{rid}: missing {key}")
            score = item["score"]
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not 0 <= score <= 100
            ):
                raise RuleLoadError(f"{rid}: score must be 0..100")
            operating_systems = item["applies_to"]
            if (
                not isinstance(operating_systems, list)
                or not operating_systems
                or set(operating_systems) - {"windows", "linux", "mac"}
            ):
                raise RuleLoadError(f"{rid}: unsupported operating systems")
            status = item.get("implementation_status", "implemented")
            if status not in {
                "implemented",
                "optional_telemetry",
                "partial",
                "unsupported",
                "defined",
            }:
                raise RuleLoadError(f"{rid}: invalid implementation status")
            expression = item["requires"]
            if item.get("configuration"):
                configuration = item["configuration"]
                if set(configuration) != {"relationship_source"}:
                    raise RuleLoadError(f"{rid}: unknown configuration")
                pairs = yaml.load(
                    (path.parent / configuration["relationship_source"]).read_text(
                        encoding="utf-8"
                    ),
                    Loader=_UniqueKeyLoader,
                )["relationships"]
                options = []
                for pair in pairs:
                    if not isinstance(pair, dict) or set(pair) != {
                        "id",
                        "applies_to",
                        "parent_names",
                        "child_names",
                    }:
                        raise RuleLoadError(f"{rid}: invalid parent-child configuration")
                    for field_name in ("applies_to", "parent_names", "child_names"):
                        if (
                            not isinstance(pair[field_name], list)
                            or not pair[field_name]
                            or not all(isinstance(name, str) and name for name in pair[field_name])
                        ):
                            raise RuleLoadError(f"{rid}: invalid {field_name}")
                    if set(pair["applies_to"]) - {"windows", "linux", "mac"}:
                        raise RuleLoadError(f"{rid}: unsupported parent-child OS")
                    if os_type in pair["applies_to"]:
                        options.append(
                            {
                                "all": [
                                    {
                                        "artifact_type": "process",
                                        "as": "child",
                                        "where": {
                                            "field": "process_name",
                                            "one_of": pair["child_names"],
                                        },
                                    },
                                    {
                                        "artifact_type": "process",
                                        "as": "parent",
                                        "scope": "global",
                                        "where": {
                                            "field": "process_name",
                                            "one_of": pair["parent_names"],
                                        },
                                    },
                                    {"left": "parent", "parent_child": "child"},
                                ]
                            }
                        )
                expression = {"any": options}
            dependencies[rid] = _expression(expression)
            edges = item.get("relationships", [])
            for edge in edges:
                if (
                    set(edge) != {"source", "target", "type"}
                    or edge["type"] not in RELATIONSHIP_TYPES
                ):
                    raise RuleLoadError(f"{rid}: invalid relationship definition")
            for key in ("benign_explanations", "limitations", "mitre_attack"):
                if not isinstance(item.get(key, []), list) or not all(
                    isinstance(x, str) for x in item.get(key, [])
                ):
                    raise RuleLoadError(f"{rid}: {key} must be a string list")
            rules[rid] = CorrelationRule(
                rid,
                item["name"],
                item["description"],
                FindingSeverity(item["severity"]),
                score / 100,
                tuple(operating_systems),
                benign_explanations=tuple(item.get("benign_explanations", [])),
                requires=expression,
                limitations=tuple(item.get("limitations", [])),
                mitre_attack=tuple(item.get("mitre_attack", [])),
                implementation_status=status,
                relationships=tuple(edges),
            )
        visited: set[str] = set()

        def visit(rid: str, stack: set[str]) -> None:
            if rid not in rules:
                raise RuleLoadError(f"Unknown rule reference: {rid}")
            if rid in stack:
                raise RuleLoadError(f"Circular dependency: {' -> '.join(sorted(stack))} -> {rid}")
            if rid in visited:
                return
            for dependency in sorted(dependencies[rid]):
                visit(dependency, stack | {rid})
            visited.add(rid)

        for rid in rules:
            visit(rid, set())
        for rule in rules.values():
            bindings = _validate_bindings(rule.requires, set(), rules)
            for edge in rule.relationships:
                if {edge["source"], edge["target"]} - bindings:
                    raise RuleLoadError(
                        f"{rule.rule_id}: relationship references unbound artifacts"
                    )
        # Keep other-OS dependencies so they can return NOT_APPLICABLE explicitly.
        return list(rules.values())
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError) as exc:
        raise RuleLoadError(f"Could not load {path}: {exc}") from exc


RELATIONSHIP_TYPES = frozenset(
    {
        "PARENT_OF",
        "CHILD_OF",
        "OWNS_MEMORY_REGION",
        "OWNS_THREAD",
        "OWNS_NETWORK_CONNECTION",
        "LOADED_MODULE",
        "ACCESSED_PROCESS",
        "CREATED_REMOTE_THREAD",
        "WROTE_PROCESS_MEMORY",
        "YARA_MATCH_IN_REGION",
        "THREAD_STARTS_IN_REGION",
        "IMAGE_MEMORY_MISMATCH",
        "PRECEDED_BY",
        "FOLLOWED_BY",
        "SAME_LOGON_SESSION",
        "SAME_PROCESS_INSTANCE",
        "CORRELATED_WITH",
    }
)


def get_default_rules_path() -> Path:
    from memsentry.resource_paths import resource_directory

    return resource_directory() / "rules" / "correlation_rules.yaml"
