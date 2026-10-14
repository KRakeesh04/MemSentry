"""Deterministic existential joins with witness bindings and cached dependencies."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import pairwise
from typing import Any

from memsentry.correlation.condition_evaluator import RELATION_OPS, relation, where
from memsentry.correlation.context_builder import ContextIndex, ProcessContext
from memsentry.correlation.normalization import NormalizedArtifact
from memsentry.correlation.rule_loader import CorrelationRule


class EvaluationState(StrEnum):
    MATCHED = "MATCHED"
    NOT_MATCHED = "NOT_MATCHED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


@dataclass(slots=True)
class Witness:
    bindings: dict[str, NormalizedArtifact] = field(default_factory=dict)
    evidence: dict[str, NormalizedArtifact] = field(default_factory=dict)
    observations: tuple[str, ...] = ()
    temporal_verified: bool = False

    def merge(self, other: Witness) -> Witness | None:
        if any(
            key in self.bindings and self.bindings[key].id != value.id
            for key, value in other.bindings.items()
        ):
            return None
        return Witness(
            {**self.bindings, **other.bindings},
            {**self.evidence, **other.evidence},
            tuple(dict.fromkeys((*self.observations, *other.observations))),
            self.temporal_verified or other.temporal_verified,
        )


@dataclass(slots=True)
class EvaluationOutcome:
    state: EvaluationState
    reason: str
    witnesses: list[Witness] = field(default_factory=list)


class EvaluationLimitError(RuntimeError):
    pass


class RuleEvaluator:
    def __init__(
        self,
        rules: list[CorrelationRule],
        index: ContextIndex,
        os_type: str,
        *,
        max_combinations: int = 100000,
    ) -> None:
        self.rules = {r.rule_id: r for r in rules}
        self.index = index
        self.os_type = os_type
        self.cache: dict[tuple[str, str], EvaluationOutcome] = {}
        self.max_combinations = max_combinations
        self.operations = 0
        self.missing_reasons: set[str] = set()
        self.selectors: dict[tuple[str, str], list[NormalizedArtifact]] = {}

    def evaluate(self, rule_id: str, context: ProcessContext) -> EvaluationOutcome:
        key = (rule_id, context.process_instance_id)
        if key in self.cache:
            return self.cache[key]
        rule = self.rules[rule_id]
        if self.os_type not in rule.applicable_os:
            outcome = EvaluationOutcome(
                EvaluationState.NOT_APPLICABLE, f"Rule does not apply to {self.os_type}"
            )
        elif rule.implementation_status == "unsupported":
            outcome = EvaluationOutcome(
                EvaluationState.INSUFFICIENT_EVIDENCE,
                "Rule requires an unsupported evidence adapter",
            )
        else:
            previous_operations = self.operations
            previous_reasons = self.missing_reasons
            self.operations = 0
            self.missing_reasons = set()
            try:
                witnesses, unknown = self._expression(rule.requires, context, Witness())
                outcome = EvaluationOutcome(
                    EvaluationState.MATCHED
                    if witnesses
                    else (
                        EvaluationState.INSUFFICIENT_EVIDENCE
                        if unknown
                        else EvaluationState.NOT_MATCHED
                    ),
                    "Conditions supported by observed artifacts"
                    if witnesses
                    else (
                        "Required telemetry, identity, address, coverage or timestamp is unavailable"
                        if unknown
                        else "Available observations do not satisfy conditions"
                    ),
                    witnesses,
                )
            except EvaluationLimitError as exc:
                outcome = EvaluationOutcome(EvaluationState.ERROR, str(exc))
            if outcome.state == EvaluationState.INSUFFICIENT_EVIDENCE and self.missing_reasons:
                outcome.reason += ": " + "; ".join(sorted(self.missing_reasons)[:20])
            self.operations = previous_operations
            self.missing_reasons = previous_reasons
        self.cache[key] = outcome
        return outcome

    def _expression(
        self,
        node: dict[str, Any],
        context: ProcessContext,
        witness: Witness,
        candidates_override: list[NormalizedArtifact] | None = None,
    ) -> tuple[list[Witness], bool]:
        self.operations += 1
        if self.operations > self.max_combinations:
            raise EvaluationLimitError(
                "Rule join budget exceeded; narrow selectors or increase max_combinations"
            )
        if "optional" in node:
            rows, _ = self._expression(node["optional"], context, witness)
            return rows or [witness], False
        if "sequence" in node:
            sequence = node["sequence"]
            events = []
            for step in sequence["steps"]:
                event = witness.bindings.get(step["binding"])
                if event is None:
                    if step.get("optional"):
                        continue
                    return [], True
                events.append(event)
            observations = list(witness.observations)
            for previous, next_event in pairwise(events):
                for op in (sequence["entity"], "before"):
                    valid = relation(self.index, previous, next_event, op, {})
                    if valid is not True:
                        if valid is None:
                            self.missing_reasons.add(
                                f"Sequence {op} requires reliable identity and timestamps"
                            )
                        return [], valid is None
                observations.append(
                    f"{previous.id} preceded {next_event.id} ({sequence['entity']})"
                )
            valid = relation(
                self.index,
                events[0],
                events[-1],
                "within_seconds",
                {"seconds": sequence["seconds"]},
            )
            if valid is not True:
                return [], valid is None
            return [Witness(witness.bindings, witness.evidence, tuple(observations), True)], False
        if set(node) & {"all", "any", "not"}:
            current = [witness]
            unknown = False
            for group in ("all", "any", "not"):
                if group not in node:
                    continue
                if group == "all":
                    for child_number, child in enumerate(node[group]):
                        next_rows: list[Witness] = []
                        step_unknown = False
                        for row in current:
                            narrowed = None
                            # For `thread/signature inside bound region`, query the address
                            # index instead of visiting every thread for every region.
                            if (
                                "artifact_type" in child
                                and child.get("scope", "process") == "process"
                                and child.get("as") not in row.bindings
                                and child_number + 1 < len(node[group])
                            ):
                                following = node[group][child_number + 1]
                                if (
                                    following.get("left") == child.get("as")
                                    and following.get("inside") in row.bindings
                                    and row.bindings[following["inside"]].instance
                                    == context.process_instance_id
                                    and context.identity_strength != "unresolved"
                                ):
                                    narrowed = self.index.address_candidates(
                                        context.process_instance_id,
                                        child["artifact_type"],
                                        following.get("field", "start_address"),
                                        row.bindings[following["inside"]],
                                    )
                            matches, missing = self._expression(child, context, row, narrowed)
                            next_rows.extend(matches)
                            step_unknown |= missing
                        current = next_rows
                        unknown |= step_unknown
                        if not current:
                            return [], unknown
                elif group == "any":
                    next_rows = []
                    for row in current:
                        for child in node[group]:
                            matches, missing = self._expression(child, context, row)
                            next_rows.extend(matches)
                            unknown |= missing
                    current = next_rows
                else:
                    for child in node[group]:
                        next_rows = []
                        for row in current:
                            matches, missing = self._expression(child, context, row)
                            unknown |= missing
                            if not matches and not missing:
                                next_rows.append(row)
                        current = next_rows
            return self._dedupe(current), unknown
        if "rule" in node:
            outcome = self.evaluate(node["rule"], context)
            if outcome.state == EvaluationState.ERROR:
                raise EvaluationLimitError(f"Dependency {node['rule']}: {outcome.reason}")
            if outcome.state == EvaluationState.INSUFFICIENT_EVIDENCE:
                self.missing_reasons.add(f"Dependency {node['rule']}: {outcome.reason}")
            return [
                merged for row in outcome.witnesses if (merged := witness.merge(row)) is not None
            ], outcome.state in {
                EvaluationState.INSUFFICIENT_EVIDENCE,
                EvaluationState.NOT_APPLICABLE,
            }
        if "artifact_type" in node:
            alias = node.get("as", node["artifact_type"])
            if candidates_override is not None:
                candidates = candidates_override
            elif alias in witness.bindings:
                candidates = [witness.bindings[alias]]
            elif node.get("scope") == "global":
                candidates = self.index.by_scope_type.get(
                    (context.artifacts[0].scope, node["artifact_type"]), []
                )
            else:
                selector_key = (context.process_instance_id, node["artifact_type"])
                if selector_key not in self.selectors:
                    self.selectors[selector_key] = [
                        a for a in context.artifacts if a.kind == node["artifact_type"]
                    ]
                candidates = self.selectors[selector_key]
            predicate = node.get(
                "where",
                {k: v for k, v in node.items() if k not in {"artifact_type", "as", "scope"}},
            )
            rows = []
            unknown = not candidates and candidates_override is None
            if unknown:
                self.missing_reasons.add(
                    f"No {node['artifact_type']} observations available for this scope"
                )
            for a in candidates:
                self.operations += 1
                if self.operations > self.max_combinations:
                    raise EvaluationLimitError(
                        "Rule selector budget exceeded; narrow selectors or increase max_combinations"
                    )
                if a.kind != node["artifact_type"]:
                    continue
                matched = where(a.data, predicate)
                unknown |= matched is None
                if matched is None:
                    self.missing_reasons.add(
                        f"{a.kind} {a.id}: required fields unavailable or invalid"
                    )
                if matched:
                    field_names = self._fields(predicate) | {
                        "timestamp",
                        "process_name",
                        "target_name",
                        "start",
                        "end",
                        "start_address",
                        "match_address",
                        "address_space",
                        "rule_name",
                        "namespace",
                        "remote_address",
                    }
                    values = {
                        name: a.data[name]
                        for name in sorted(field_names)
                        if a.data.get(name) is not None
                    }
                    observation = f"{a.kind} {a.id}: " + (
                        json.dumps(values, sort_keys=True, default=str)
                        if values
                        else "observed source record"
                    )
                    merged = witness.merge(Witness({alias: a}, {a.id: a}, (observation,)))
                    if merged:
                        rows.append(merged)
            return rows, unknown
        op = next(key for key in node if key in RELATION_OPS)
        left, right = witness.bindings.get(node["left"]), witness.bindings.get(node[op])
        if left is None or right is None:
            return [], True
        matched = relation(self.index, left, right, op, node)
        if matched is None:
            self.missing_reasons.add(
                f"{op} between {left.id} and {right.id}: identity, address, coverage or time is unavailable"
            )
        if matched:
            return [
                Witness(
                    witness.bindings,
                    witness.evidence,
                    (*witness.observations, f"{left.id} {op} {right.id}"),
                    witness.temporal_verified or op in {"before", "after"},
                )
            ], False
        return [], matched is None

    @staticmethod
    def _fields(predicate: dict[str, Any]) -> set[str]:
        names = {predicate["field"]} if "field" in predicate else set()
        for group in ("all", "any", "not"):
            for child in predicate.get(group, []):
                names |= RuleEvaluator._fields(child)
        return names

    @staticmethod
    def _dedupe(rows: list[Witness]) -> list[Witness]:
        unique = {tuple(sorted((k, a.id) for k, a in row.bindings.items())): row for row in rows}
        return [unique[key] for key in sorted(unique)]
