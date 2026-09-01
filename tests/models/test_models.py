from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from memsentry.models.evidence import Evidence, EvidenceCreate, EvidenceOS
from memsentry.models.finding import Finding, FindingCreate, FindingSeverity


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

    # Test mixed case normalization
    mixed_case_sha = "AaBbCcDd" + "e" * 56
    ev_mixed = EvidenceCreate(
        case_id=case_id,
        original_filename="sample.raw",
        file_path=Path("/tmp/sample.raw"),
        file_size_bytes=1024,
        sha256=mixed_case_sha,
    )
    assert ev_mixed.sha256 == mixed_case_sha.lower()

    # Test whitespace stripping
    whitespace_sha = "  " + valid_sha + "  "
    ev_ws = EvidenceCreate(
        case_id=case_id,
        original_filename="sample.raw",
        file_path=Path("/tmp/sample.raw"),
        file_size_bytes=1024,
        sha256=whitespace_sha,
    )
    assert ev_ws.sha256 == valid_sha

    # Test too short
    with pytest.raises(ValidationError):
        EvidenceCreate(
            case_id=case_id,
            original_filename="sample.raw",
            file_path=Path("/tmp/sample.raw"),
            file_size_bytes=1024,
            sha256="a" * 63,
        )

    # Test too long
    with pytest.raises(ValidationError):
        EvidenceCreate(
            case_id=case_id,
            original_filename="sample.raw",
            file_path=Path("/tmp/sample.raw"),
            file_size_bytes=1024,
            sha256="a" * 65,
        )

    # Test invalid hex character in middle
    with pytest.raises(ValidationError):
        EvidenceCreate(
            case_id=case_id,
            original_filename="sample.raw",
            file_path=Path("/tmp/sample.raw"),
            file_size_bytes=1024,
            sha256="a" * 31 + "g" + "a" * 32,
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

    # Test zero file size (boundary case - should be valid)
    ev_zero = EvidenceCreate(
        case_id=uuid4(),
        original_filename="empty.raw",
        file_path=Path("/tmp/empty.raw"),
        file_size_bytes=0,
        sha256=valid_sha,
    )
    assert ev_zero.file_size_bytes == 0


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

    # Boundary values
    f2 = FindingCreate(
        analysis_run_id=analysis_run_id,
        rule_id="RULE-002",
        title="Test",
        description="Test",
        severity=FindingSeverity.LOW,
        confidence=0.0,
    )
    assert f2.confidence == 0.0

    f3 = FindingCreate(
        analysis_run_id=analysis_run_id,
        rule_id="RULE-003",
        title="Test",
        description="Test",
        severity=FindingSeverity.HIGH,
        confidence=1.0,
    )
    assert f3.confidence == 1.0

    # None confidence (should be valid)
    f4 = FindingCreate(
        analysis_run_id=analysis_run_id,
        rule_id="RULE-004",
        title="Test",
        description="Test",
        severity=FindingSeverity.MEDIUM,
        confidence=None,
    )
    assert f4.confidence is None

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


def test_evidence_model_sha256_validation() -> None:
    """Test that Evidence model also validates SHA256."""
    valid_sha = "c" * 64
    
    # Valid SHA256
    evidence = Evidence(
        id=uuid4(),
        case_id=uuid4(),
        original_filename="test.raw",
        file_path=Path("/tmp/test.raw"),
        file_size_bytes=1024,
        sha256=valid_sha,
        evidence_os=EvidenceOS.WINDOWS,
        integrity_status="verified",
        registered_at="2026-01-01T00:00:00Z",
    )
    assert evidence.sha256 == valid_sha

    # Invalid SHA256
    with pytest.raises(ValidationError):
        Evidence(
            id=uuid4(),
            case_id=uuid4(),
            original_filename="test.raw",
            file_path=Path("/tmp/test.raw"),
            file_size_bytes=1024,
            sha256="invalid",
            evidence_os=EvidenceOS.WINDOWS,
            integrity_status="verified",
            registered_at="2026-01-01T00:00:00Z",
        )


def test_finding_model_confidence_validation() -> None:
    """Test that Finding model also validates confidence."""
    # Valid confidence
    finding = Finding(
        id=uuid4(),
        analysis_run_id=uuid4(),
        rule_id="RULE-001",
        title="Test",
        description="Test",
        severity="high",
        confidence=0.5,
        created_at="2026-01-01T00:00:00Z",
    )
    assert finding.confidence == 0.5

    # Invalid confidence
    with pytest.raises(ValidationError):
        Finding(
            id=uuid4(),
            analysis_run_id=uuid4(),
            rule_id="RULE-001",
            title="Test",
            description="Test",
            severity="high",
            confidence=1.5,
            created_at="2026-01-01T00:00:00Z",
        )
