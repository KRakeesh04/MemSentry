from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from memsentry.models.evidence import EvidenceCreate, EvidenceOS
from memsentry.models.finding import FindingCreate, FindingSeverity


def test_evidence_create_sha256_validation() -> None:
    valid_sha = "a" * 64
    case_id = uuid4()

    evidence_data = EvidenceCreate(
        case_id=case_id,
        original_filename="sample.raw",
        file_path=Path("/tmp/sample.raw"),
        file_size_bytes=1024,
        sha256=valid_sha,
        evidence_os=EvidenceOS.WINDOWS,
    )
    assert evidence_data.sha256 == valid_sha

    with pytest.raises(ValidationError):
        EvidenceCreate(
            case_id=case_id,
            original_filename="sample.raw",
            file_path=Path("/tmp/sample.raw"),
            file_size_bytes=1024,
            sha256="invalid_hex",
        )


def test_evidence_create_negative_file_size() -> None:
    valid_sha = "b" * 64
    with pytest.raises(ValidationError):
        EvidenceCreate(
            case_id=uuid4(),
            original_filename="sample.raw",
            file_path=Path("/tmp/sample.raw"),
            file_size_bytes=-1,
            sha256=valid_sha,
        )


def test_finding_create_confidence_validation() -> None:
    analysis_run_id = uuid4()

    # Valid confidence
    f1 = FindingCreate(
        analysis_run_id=analysis_run_id,
        rule_id="RULE-001",
        title="Suspicious Process",
        description="Found hidden process",
        severity=FindingSeverity.HIGH,
        confidence=0.85,
    )
    assert f1.confidence == 0.85

    # Out of bound confidence (> 1.0)
    with pytest.raises(ValidationError):
        FindingCreate(
            analysis_run_id=analysis_run_id,
            rule_id="RULE-001",
            title="Suspicious Process",
            description="Found hidden process",
            severity=FindingSeverity.HIGH,
            confidence=1.5,
        )

    # Negative confidence (< 0.0)
    with pytest.raises(ValidationError):
        FindingCreate(
            analysis_run_id=analysis_run_id,
            rule_id="RULE-001",
            title="Suspicious Process",
            description="Found hidden process",
            severity=FindingSeverity.HIGH,
            confidence=-0.1,
        )
