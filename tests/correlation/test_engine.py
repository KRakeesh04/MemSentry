"""Tests for the correlation engine."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from uuid import uuid4

from memsentry.correlation import (
    CorrelationEngine,
    CorrelationResult,
    CorrelationRule,
    load_rules_from_yaml,
)
from memsentry.models.artifact import Artifact


def test_correlation_engine_initialization() -> None:
    """Test that correlation engine initializes correctly."""
    engine = CorrelationEngine(os_type="windows")
    assert engine.os_type == "windows"
    # Should load rules from YAML file or fallback to default rules
    assert len(engine.rules) > 0
    # Should have at least the 8 required rules
    assert len(engine.rules) >= 8


def test_correlation_with_no_artifacts() -> None:
    """Test correlation with no artifacts returns empty result with warning."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()
    result = engine.correlate([], analysis_run_id)

    assert isinstance(result, CorrelationResult)
    assert len(result.findings) == 0
    assert len(result.relationships) == 0
    assert len(result.process_contexts) == 0
    assert len(result.warnings) == 1
    assert "No artifacts provided" in result.warnings[0]


def test_correlation_with_process_artifacts() -> None:
    """Test correlation builds process contexts correctly."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    # Create test artifacts
    process_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "test.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate([process_artifact], analysis_run_id)

    assert len(result.process_contexts) == 1
    assert 1234 in result.process_contexts
    assert result.process_contexts[1234].process_name == "test.exe"
    assert result.process_contexts[1234].ppid == 1000


def test_correlation_rule_ms_r001_executable_private_memory() -> None:
    """Test MS-R001 rule: Executable Private Memory."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    # Create process with executable private memory
    process_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "suspicious.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    memory_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="memory_region",
        pid=1234,
        original_data={
            "protection": "PAGE_EXECUTE_READWRITE",
            "private_memory": True,
            "start": "0x1000",
            "end": "0x2000",
        },
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate([process_artifact, memory_artifact], analysis_run_id)

    # Should trigger MS-R001
    executable_memory_findings = [
        f for f in result.findings if f.rule_id == "MS-R001"
    ]
    assert len(executable_memory_findings) == 1
    assert "executable" in executable_memory_findings[0].title.lower()
    assert ". Process:" in executable_memory_findings[0].description
    assert ".. Process:" not in executable_memory_findings[0].description


def test_correlation_rule_ms_r002_memory_with_network() -> None:
    """Test MS-R002 rule: Executable Private Memory with Network Activity."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    # Create process with executable memory and network connections
    process_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "malware.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    memory_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="memory_region",
        pid=1234,
        original_data={
            "protection": "PAGE_EXECUTE_READ",
            "private_memory": True,
        },
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    network_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="network_connection",
        pid=1234,
        original_data={
            "local_address": "192.168.1.100",
            "local_port": 12345,
            "remote_address": "10.0.0.1",
            "remote_port": 443,
        },
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate(
        [process_artifact, memory_artifact, network_artifact], analysis_run_id
    )

    # Should trigger MS-R002
    network_memory_findings = [f for f in result.findings if f.rule_id == "MS-R002"]
    assert len(network_memory_findings) == 1
    assert "network" in network_memory_findings[0].title.lower()


def test_correlation_rule_ms_r004_yara_match() -> None:
    """Test MS-R004 rule: YARA Match in Suspicious Region."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    # Create process with YARA signature match
    process_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "suspicious.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    yara_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="signature_match",
        pid=1234,
        original_data={
            "rule": "Malware_Signature",
            "offset": "0x1500",
        },
        provenance={"source": "yara"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate([process_artifact, yara_artifact], analysis_run_id)

    # Should trigger MS-R004
    yara_findings = [f for f in result.findings if f.rule_id == "MS-R004"]
    assert len(yara_findings) == 1
    assert "yara" in yara_findings[0].title.lower()


def test_correlation_rule_ms_r006_unbacked_module() -> None:
    """Test MS-R006 rule: Unbacked executable module."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    # Create process with unbacked executable module
    process_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "suspicious.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    module_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="module",
        pid=1234,
        original_data={
            "executable": True,
            "path": None,  # Unbacked module
        },
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate([process_artifact, module_artifact], analysis_run_id)

    # Should trigger MS-R006
    unbacked_findings = [f for f in result.findings if f.rule_id == "MS-R006"]
    assert len(unbacked_findings) == 1
    assert "Unbacked" in unbacked_findings[0].title


def test_correlation_parent_child_relationships() -> None:
    """Test that parent-child relationships are detected."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    # Create parent and child processes
    parent_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1000,
        original_data={"process_name": "parent.exe", "ppid": 500},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    child_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "child.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate([parent_artifact, child_artifact], analysis_run_id)

    # Should detect parent-child relationship
    parent_child_relationships = [
        r for r in result.relationships if r.relationship_type == "parent_child"
    ]
    assert len(parent_child_relationships) == 1


def test_correlation_suspicious_parent_child() -> None:
    """Test MS-R005 rule: Suspicious parent-child relationship."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    # Create suspicious parent-child relationship (winword.exe -> powershell.exe)
    parent_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1000,
        original_data={"process_name": "winword.exe", "ppid": 500},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    child_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "powershell.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate([parent_artifact, child_artifact], analysis_run_id)

    # Should trigger MS-R005 for suspicious parent-child
    suspicious_parent_findings = [f for f in result.findings if f.rule_id == "MS-R005"]
    assert len(suspicious_parent_findings) == 1
    assert "parent" in suspicious_parent_findings[0].title.lower()


def test_correlation_os_specific_rules() -> None:
    """Test that OS-specific rules are only applied for applicable OS."""
    windows_engine = CorrelationEngine(os_type="windows")
    linux_engine = CorrelationEngine(os_type="linux")

    windows_rules_ids = [r.rule_id for r in windows_engine.rules]
    linux_rules_ids = [r.rule_id for r in linux_engine.rules]

    # Check that both engines have rules loaded
    assert len(windows_rules_ids) > 0
    assert len(linux_rules_ids) > 0

    # MS-R003 is Windows-only in both YAML and fallback rules
    assert "MS-R003" in windows_rules_ids
    # When using fallback rules, MS-R003 is Windows-only
    # Check that it's not in Linux rules or verify OS filtering works
    if "MS-R003" in linux_rules_ids:
        # If using YAML rules, check that the rule is filtered by OS
        ms_r003_rule = next(r for r in linux_engine.rules if r.rule_id == "MS-R003")
        assert "linux" not in ms_r003_rule.applicable_os


def test_correlation_multiple_suspicious_indicators() -> None:
    """Test MS-R007 rule: Suspicious command line with network activity."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    # Create process with suspicious command line and network connections
    process_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "suspicious.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    command_line_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="command_line",
        pid=1234,
        original_data={"command_line": "powershell -EncodedCommand ..."},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    network_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="network_connection",
        pid=1234,
        original_data={
            "local_address": "192.168.1.100",
            "local_port": 12345,
            "remote_address": "10.0.0.1",
            "remote_port": 443,
        },
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate(
        [process_artifact, command_line_artifact, network_artifact], analysis_run_id
    )

    # Should trigger MS-R007 due to suspicious command line with network
    command_line_findings = [f for f in result.findings if f.rule_id == "MS-R007"]
    assert len(command_line_findings) == 1


def test_correlation_scoring() -> None:
    """Test that findings have appropriate confidence scores."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    process_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "test.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    memory_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="memory_region",
        pid=1234,
        original_data={
            "protection": "PAGE_EXECUTE_READ",
            "private_memory": True,
        },
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate([process_artifact, memory_artifact], analysis_run_id)

    # Check that findings have confidence scores
    for finding in result.findings:
        assert finding.confidence is not None
        assert 0.0 <= finding.confidence <= 1.0


def test_correlation_findings_metadata() -> None:
    """Test that findings include required metadata."""
    engine = CorrelationEngine(os_type="windows")
    analysis_run_id = uuid4()

    process_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={"process_name": "test.exe", "ppid": 1000},
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    memory_artifact = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="memory_region",
        pid=1234,
        original_data={
            "protection": "PAGE_EXECUTE_READ",
            "private_memory": True,
        },
        provenance={"source": "test"},
        created_at=datetime.now(UTC),
    )

    result = engine.correlate([process_artifact, memory_artifact], analysis_run_id)

    # Check that findings have required metadata
    for finding in result.findings:
        assert finding.rule_id
        assert finding.title
        assert finding.description
        assert finding.severity
        assert finding.analysis_run_id == analysis_run_id


def test_rule_loader_from_yaml() -> None:
    """Test that rules can be loaded from YAML file."""
    # Create a temporary YAML file for testing
    yaml_content = """
version: "1.0.0"
name: "Test correlation rules"
description: "Test rules for unit testing"

rules:
  - id: MS-R001
    name: Executable private memory
    description: A process owns a private memory region with executable protection.
    severity: medium
    score: 25
    implementation_status: defined
    applies_to: [windows, linux, mac]
    requires:
      all:
        - artifact_type: memory_region
          field: private
          equals: true
    group_by: pid
    benign_explanations:
      - JIT compilation
      - Runtime unpacking
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        rules = load_rules_from_yaml(temp_path, os_type="windows")
        assert len(rules) > 0
        # Check that loaded rules are CorrelationRule instances
        assert all(isinstance(rule, CorrelationRule) for rule in rules)
        # Check that MS-R001 is loaded
        rule_ids = [r.rule_id for r in rules]
        assert "MS-R001" in rule_ids
    finally:
        # Clean up the temporary file
        os.unlink(temp_path)
