"""Evidence-backed correlation over persisted artifacts; no plugin execution here."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from memsentry.correlation.context_builder import ContextIndex, stable_id
from memsentry.correlation.context_builder import ProcessContext as ProcessContext
from memsentry.correlation.normalization import normalize
from memsentry.correlation.risk_scoring import score_evidence
from memsentry.correlation.rule_evaluator import EvaluationOutcome, EvaluationState, RuleEvaluator
from memsentry.correlation.rule_loader import get_default_rules_path, load_rules_from_yaml
from memsentry.models.artifact import Artifact
from memsentry.models.finding import FindingCreate
from memsentry.volatility.os_utils import normalise_os


@dataclass(frozen=True, slots=True)
class ArtifactRelationship:
    source_artifact_id: UUID
    target_artifact_id: UUID
    relationship_type: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return stable_id(
            [str(self.source_artifact_id), str(self.target_artifact_id), self.relationship_type]
        )


@dataclass
class CorrelationResult:
    findings: list[FindingCreate] = field(default_factory=list)
    relationships: list[ArtifactRelationship] = field(default_factory=list)
    # Unique PIDs remain integer keys; ambiguous PIDs use stable instance IDs.
    process_contexts: dict[int | str, ProcessContext] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    finding_artifact_ids: list[list[UUID]] = field(default_factory=list)
    evaluations: dict[str, dict[str, EvaluationOutcome]] = field(default_factory=dict)
    finding_details: list[dict[str, Any]] = field(default_factory=list)


class CorrelationEngine:
    def __init__(
        self,
        os_type: str = "windows",
        rules_path: str | Path | None = None,
        *,
        max_combinations: int = 100000,
    ) -> None:
        if max_combinations < 1:
            raise ValueError("max_combinations must be positive")
        self.max_combinations = max_combinations
        self.os_type = normalise_os(os_type)
        self.rules = load_rules_from_yaml(rules_path or get_default_rules_path(), self.os_type)

    def correlate(self, artifacts: list[Artifact], analysis_run_id: UUID) -> CorrelationResult:
        result = CorrelationResult()
        if not artifacts:
            result.warnings.append("No artifacts provided for correlation")
            return result
        if any(a.analysis_run_id != analysis_run_id for a in artifacts):
            raise ValueError("Correlation artifacts must belong to the requested analysis run")
        by_id: dict[UUID, Artifact] = {}
        for artifact in artifacts:
            if artifact.id in by_id and artifact != by_id[artifact.id]:
                raise ValueError(f"Conflicting artifact records for {artifact.id}")
            by_id[artifact.id] = artifact
        index = ContextIndex([normalize(a) for a in by_id.values()])
        result.warnings.extend(index.warnings)
        counts = Counter(c.pid for c in index.contexts.values())
        result.process_contexts = {
            (c.pid if c.pid >= 0 and counts[c.pid] == 1 else key): c
            for key, c in index.contexts.items()
        }
        evaluator = RuleEvaluator(
            self.rules, index, self.os_type, max_combinations=self.max_combinations
        )
        views = {a.artifact.id: a for a in index.artifacts}
        edges: dict[str, ArtifactRelationship] = {}

        def edge(
            source: Artifact,
            target: Artifact,
            kind: str,
            evidence_ids: list[str],
            method: str,
            confidence: float = 0.65,
        ) -> str:
            item = ArtifactRelationship(
                source.id,
                target.id,
                kind,
                confidence,
                {
                    "supporting_artifact_ids": sorted(set(evidence_ids)),
                    "correlation_method": method,
                    "canonical_type": "PARENT_OF" if kind == "parent_child" else kind,
                    "evidence_source": [source.provenance, target.provenance],
                    "observed": method == "resolved target identity",
                    "source_timestamp": views[source.id].data["timestamp_utc"].isoformat()
                    if views[source.id].data.get("timestamp_utc")
                    else None,
                    "target_timestamp": views[target.id].data["timestamp_utc"].isoformat()
                    if views[target.id].data.get("timestamp_utc")
                    else None,
                    "analysis_run_id": str(analysis_run_id),
                },
            )
            edges[item.id] = item
            return item.id

        for context in index.contexts.values():
            processes = [a for a in context.artifacts if a.kind in {"process", "process_tree"}]
            if processes:
                anchor = processes[0]
                for a in context.artifacts:
                    kind = {
                        "memory_region": "OWNS_MEMORY_REGION",
                        "thread": "OWNS_THREAD",
                        "module": "LOADED_MODULE",
                        "network_connection": "OWNS_NETWORK_CONNECTION",
                    }.get(a.kind)
                    if kind and index.same(anchor, a) is True:
                        edge(
                            anchor.artifact,
                            a.artifact,
                            kind,
                            [anchor.id, a.id],
                            "scoped_process_identity",
                        )
                parent = index.resolve(anchor, "parent")
                parents = [
                    a
                    for a in index.by_instance.get(parent or "", [])
                    if a.kind in {"process", "process_tree"}
                ]
                if parents and parent != anchor.instance:
                    edge(
                        parents[0].artifact,
                        anchor.artifact,
                        "parent_child",
                        [parents[0].id, anchor.id],
                        "PARENT_OF: scoped parent identity",
                    )
            for a in context.artifacts:
                kind = {
                    "process_access": "ACCESSED_PROCESS",
                    "remote_thread": "CREATED_REMOTE_THREAD",
                    "process_memory_write": "WROTE_PROCESS_MEMORY",
                }.get(a.kind)
                target_identity = index.resolve(a, "target")
                targets = [
                    b
                    for b in index.by_instance.get(target_identity or "", [])
                    if b.kind in {"process", "process_tree"}
                ]
                if kind and targets:
                    edge(
                        a.artifact,
                        targets[0].artifact,
                        kind,
                        [a.id, targets[0].id],
                        "resolved target identity",
                    )

        seen: set[tuple[str, tuple[str, ...]]] = set()
        for identity, context in sorted(index.contexts.items()):
            result.evaluations[identity] = {}
            for rule in self.rules:
                outcome = evaluator.evaluate(rule.rule_id, context)
                result.evaluations[identity][rule.rule_id] = outcome
                if outcome.state == EvaluationState.ERROR:
                    result.warnings.append(f"{rule.rule_id} {identity}: {outcome.reason}")
                if outcome.state != EvaluationState.MATCHED:
                    continue
                evidence = {key: a for row in outcome.witnesses for key, a in row.evidence.items()}
                ids = tuple(sorted(evidence))
                if not ids or (rule.rule_id, ids) in seen:
                    continue
                seen.add((rule.rule_id, ids))
                supporting = set()
                for row in outcome.witnesses:
                    for definition in rule.relationships:
                        source, target = (
                            row.bindings.get(definition["source"]),
                            row.bindings.get(definition["target"]),
                        )
                        if source and target:
                            supporting.add(
                                edge(
                                    source.artifact,
                                    target.artifact,
                                    definition["type"],
                                    list(row.evidence),
                                    f"YAML {rule.rule_id}",
                                )
                            )
                observations = sorted(
                    {text for row in outcome.witnesses for text in row.observations}
                )
                temporal = any(row.temporal_verified for row in outcome.witnesses)
                risk, confidence, contributions = score_evidence(
                    list(evidence.values()), rule.base_score, temporal=temporal
                )
                times = sorted(
                    a.data["timestamp_utc"].isoformat()
                    for a in evidence.values()
                    if a.data.get("timestamp_utc")
                )
                limitations = list(rule.limitations)
                if not contributions["strong_identity"]:
                    limitations.append(
                        "Identity uses a scoped snapshot fallback or incomplete event identity."
                    )
                details = {
                    "rule_id": rule.rule_id,
                    "rule_definition_sha256": hashlib.sha256(
                        json.dumps(asdict(rule), sort_keys=True).encode()
                    ).hexdigest(),
                    "analysis_run_id": str(analysis_run_id),
                    "risk_score": risk,
                    "confidence": round(confidence, 3),
                    "affected_process_instance": identity,
                    "matched_artifact_ids": list(ids),
                    "supporting_relationship_ids": sorted(supporting),
                    "observed_indicators": observations,
                    "relationships": [
                        {
                            "id": edges[key].id,
                            "source_artifact_id": str(edges[key].source_artifact_id),
                            "target_artifact_id": str(edges[key].target_artifact_id),
                            "relationship_type": edges[key].relationship_type,
                            "confidence": edges[key].confidence,
                            "metadata": edges[key].metadata,
                        }
                        for key in sorted(supporting)
                    ],
                    "inferred_behavior": rule.description,
                    "limitations": limitations,
                    "benign_explanations": list(rule.benign_explanations),
                    "mitre_attack_mapping": list(rule.mitre_attack),
                    "temporal_window": {"start": times[0], "end": times[-1]} if times else None,
                    "score_contributions": contributions,
                }
                description = (
                    f"Inference: {rule.description}\nProcess: {context.process_name or 'unknown'} (PID: {context.pid if context.pid >= 0 else 'unavailable'}).\nObserved evidence:\n"
                    + "\n".join(observations)
                )
                description += (
                    f"\nInvestigative risk: {risk}/100. Evidence confidence: {confidence:.3f}."
                )
                if limitations:
                    description += "\nLimitations: " + "; ".join(limitations)
                if rule.benign_explanations:
                    description += "\nPossible benign explanations: " + "; ".join(
                        rule.benign_explanations
                    )
                result.findings.append(
                    FindingCreate(
                        analysis_run_id=analysis_run_id,
                        finding_id=UUID(stable_id([str(analysis_run_id), rule.rule_id, identity, ids])),
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=description,
                        severity=rule.severity,
                        confidence=round(confidence, 3),
                        correlation_details=details,
                    )
                )
                result.finding_artifact_ids.append([UUID(value) for value in ids])
                result.finding_details.append(details)
        result.relationships = [edges[key] for key in sorted(edges)]
        missing = Counter(
            rid
            for outcomes in result.evaluations.values()
            for rid, value in outcomes.items()
            if value.state == EvaluationState.INSUFFICIENT_EVIDENCE
        )
        if missing:
            result.warnings.append(
                "Insufficient evidence in one or more contexts: "
                + ", ".join(sorted(missing))
                + ". See structured evaluations; missing telemetry is not a negative result."
            )
        return result
