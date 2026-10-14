"""Deterministic triage scoring, separate from severity and YAML priority.

Confidence = min reliability * (0.55 + 0.08 per additional artifact class,
maximum three) + 0.10 for complete lifetime identity + 0.05 for validated temporal
ordering, bounded to [0.10, 0.90]. Explicit benign context multiplies confidence
and priority by 0.60. Evidence classes are a conservative diversity measure, not
an assertion of statistical independence. Dependencies and duplicate rows never
add points. This is a transparent heuristic, not a calibrated probability.
"""

from __future__ import annotations

from typing import Any

from memsentry.correlation.normalization import NormalizedArtifact


def score_evidence(
    evidence: list[NormalizedArtifact], priority: float, *, temporal: bool
) -> tuple[int, float, dict[str, Any]]:
    classes = {a.kind for a in evidence}
    source_observations = {
        (
            a.scope,
            str(a.data.get("source_file") or a.artifact.plugin_run_id),
            str(a.data.get("provider")),
            str(a.data.get("channel")),
            str(a.data.get("source_record_id", a.data.get("source_row", a.id))),
        )
        for a in evidence
    }
    indicator_count = min(len(classes), len(source_observations))
    strong = all(a.identity_strength in {"guid", "created", "instance"} for a in evidence)
    reliability = min(min(1.0, a.data["evidence_reliability"]) for a in evidence)
    confidence = min(
        0.9,
        max(
            0.1,
            reliability * (0.55 + min(indicator_count - 1, 3) * 0.08)
            + (0.1 if strong else 0)
            + (0.05 if temporal else 0),
        ),
    )
    benign = any(
        a.data.get("known_benign") is True or a.data.get("authorized_maintenance") is True
        for a in evidence
    )
    discount = 0.6 if benign else 1
    return (
        round(priority * 100 * discount),
        round(confidence * discount, 3),
        {
            "configured_priority": priority * 100,
            "independent_artifact_classes": indicator_count,
            "minimum_reliability": reliability,
            "strong_identity": strong,
            "validated_temporal_order": temporal,
            "benign_context_discount": benign,
            "confidence_is_calibrated_probability": False,
        },
    )
