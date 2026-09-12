"""End-to-end test demonstrating correlation findings with printable output."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from memsentry.correlation import CorrelationEngine
from memsentry.models.artifact import Artifact


def create_mock_artifacts(analysis_run_id: UUID) -> list[Artifact]:
    """Create realistic mock artifacts for testing correlation."""
    artifacts = []

    # Create a suspicious process (mimicking malware behavior)
    suspicious_process = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1234,
        original_data={
            "process_name": "suspicious.exe",
            "ppid": 1000,
            "created_at": "2024-01-15T10:30:00Z",
            "exited_at": None,
        },
        provenance={"source": "windows.pslist.PsList", "row": 1},
        created_at=datetime.now(UTC),
    )
    artifacts.append(suspicious_process)

    # Create parent process (cmd.exe)
    parent_process = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=1000,
        original_data={
            "process_name": "cmd.exe",
            "ppid": 500,
            "created_at": "2024-01-15T10:29:00Z",
            "exited_at": None,
        },
        provenance={"source": "windows.pslist.PsList", "row": 2},
        created_at=datetime.now(UTC),
    )
    artifacts.append(parent_process)

    # Create executable private memory regions (suspicious)
    memory_region_1 = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="memory_region",
        pid=1234,
        original_data={
            "protection": "PAGE_EXECUTE_READWRITE",
            "private_memory": True,
            "start": "0x1000000",
            "end": "0x1001000",
            "tag": "MEM_PRIVATE",
        },
        provenance={"source": "windows.malfind.Malfind", "row": 1},
        created_at=datetime.now(UTC),
    )
    artifacts.append(memory_region_1)

    memory_region_2 = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="memory_region",
        pid=1234,
        original_data={
            "protection": "PAGE_EXECUTE_READ",
            "private_memory": True,
            "start": "0x2000000",
            "end": "0x2002000",
            "tag": "MEM_PRIVATE",
        },
        provenance={"source": "windows.malfind.Malfind", "row": 2},
        created_at=datetime.now(UTC),
    )
    artifacts.append(memory_region_2)

    # Create network connections (suspicious when combined with executable memory)
    network_conn_1 = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="network_connection",
        pid=1234,
        original_data={
            "protocol": "TCP",
            "local_address": "192.168.1.100",
            "local_port": 49152,
            "remote_address": "10.0.0.1",
            "remote_port": 443,
            "state": "ESTABLISHED",
        },
        provenance={"source": "windows.netscan.NetScan", "row": 1},
        created_at=datetime.now(UTC),
    )
    artifacts.append(network_conn_1)

    network_conn_2 = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="network_connection",
        pid=1234,
        original_data={
            "protocol": "TCP",
            "local_address": "192.168.1.100",
            "local_port": 49153,
            "remote_address": "10.0.0.2",
            "remote_port": 80,
            "state": "ESTABLISHED",
        },
        provenance={"source": "windows.netscan.NetScan", "row": 2},
        created_at=datetime.now(UTC),
    )
    artifacts.append(network_conn_2)

    # Create YARA signature match
    yara_match = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="signature_match",
        pid=1234,
        original_data={
            "rule": "Malware_Generic",
            "namespace": "default",
            "tags": ["malware", "suspicious"],
            "offset": "0x1000500",
            "meta": {"description": "Generic malware pattern"},
        },
        provenance={"source": "yara", "plugin": "yara.scan"},
        created_at=datetime.now(UTC),
    )
    artifacts.append(yara_match)

    # Create command line with suspicious indicators
    command_line = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="command_line",
        pid=1234,
        original_data={
            "command_line": "powershell -EncodedCommand JABjAHkAcAB0AG... [obfuscated]"
        },
        provenance={"source": "windows.cmdline.CmdLine", "row": 1},
        created_at=datetime.now(UTC),
    )
    artifacts.append(command_line)

    # Create unbacked module
    unbacked_module = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="module",
        pid=1234,
        original_data={
            "executable": True,
            "path": None,  # Unbacked module
            "base_address": "0x3000000",
            "size": 0x1000,
        },
        provenance={"source": "windows.dlllist.DllList", "row": 1},
        created_at=datetime.now(UTC),
    )
    artifacts.append(unbacked_module)

    # Create some benign processes for comparison
    benign_process_1 = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=2000,
        original_data={
            "process_name": "explorer.exe",
            "ppid": 1,
            "created_at": "2024-01-15T09:00:00Z",
            "exited_at": None,
        },
        provenance={"source": "windows.pslist.PsList", "row": 3},
        created_at=datetime.now(UTC),
    )
    artifacts.append(benign_process_1)

    benign_process_2 = Artifact(
        id=uuid4(),
        analysis_run_id=analysis_run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=3000,
        original_data={
            "process_name": "svchost.exe",
            "ppid": 1,
            "created_at": "2024-01-15T09:05:00Z",
            "exited_at": None,
        },
        provenance={"source": "windows.pslist.PsList", "row": 4},
        created_at=datetime.now(UTC),
    )
    artifacts.append(benign_process_2)

    return artifacts


def generate_printable_report(
    correlation_result, output_dir: Path, analysis_run_id: UUID
) -> None:
    """Generate printable files showing correlation results."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Summary Report (Human-readable text)
    summary_path = output_dir / "correlation_summary.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("MEMSENTRY CORRELATION ANALYSIS REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Analysis Run ID: {analysis_run_id}\n")
        f.write(f"Timestamp: {datetime.now(UTC).isoformat()}\n")
        f.write("OS Type: Windows\n\n")

        f.write(f"Total Findings: {len(correlation_result.findings)}\n")
        f.write(f"Total Relationships: {len(correlation_result.relationships)}\n")
        f.write(f"Total Processes Analyzed: {len(correlation_result.process_contexts)}\n\n")

        if correlation_result.warnings:
            f.write("WARNINGS:\n")
            for warning in correlation_result.warnings:
                f.write(f"  - {warning}\n")
            f.write("\n")

        f.write("-" * 80 + "\n")
        f.write("FINDINGS DETAILS\n")
        f.write("-" * 80 + "\n\n")

        for i, finding in enumerate(correlation_result.findings, 1):
            f.write(f"Finding #{i}:\n")
            f.write(f"  Rule ID: {finding.rule_id}\n")
            f.write(f"  Title: {finding.title}\n")
            f.write(f"  Severity: {finding.severity}\n")
            f.write(f"  Confidence: {finding.confidence:.2f}\n")
            f.write(f"  Description: {finding.description}\n\n")

        f.write("-" * 80 + "\n")
        f.write("RELATIONSHIPS\n")
        f.write("-" * 80 + "\n\n")

        for i, relationship in enumerate(correlation_result.relationships, 1):
            f.write(f"Relationship #{i}:\n")
            f.write(f"  Type: {relationship.relationship_type}\n")
            f.write(f"  Confidence: {relationship.confidence:.2f}\n")
            f.write(f"  Metadata: {relationship.metadata}\n\n")

        f.write("-" * 80 + "\n")
        f.write("PROCESS CONTEXTS\n")
        f.write("-" * 80 + "\n\n")

        for pid, context in correlation_result.process_contexts.items():
            f.write(f"Process PID {pid}:\n")
            f.write(f"  Name: {context.process_name}\n")
            f.write(f"  PPID: {context.ppid}\n")
            f.write(f"  Memory Regions: {len(context.memory_regions)}\n")
            f.write(f"  Network Connections: {len(context.network_connections)}\n")
            f.write(f"  Threads: {len(context.threads)}\n")
            f.write(f"  Modules: {len(context.modules)}\n")
            f.write(f"  YARA Matches: {len(context.signature_matches)}\n")
            f.write(f"  Command Line: {'Yes' if context.command_line else 'No'}\n\n")

    # 2. JSON Report (Machine-readable)
    json_path = output_dir / "correlation_results.json"
    with json_path.open("w", encoding="utf-8") as f:
        results = {
            "analysis_run_id": str(analysis_run_id),
            "timestamp": datetime.now(UTC).isoformat(),
            "os_type": "windows",
            "summary": {
                "total_findings": len(correlation_result.findings),
                "total_relationships": len(correlation_result.relationships),
                "total_processes": len(correlation_result.process_contexts),
                "warnings": correlation_result.warnings,
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "confidence": f.confidence,
                }
                for f in correlation_result.findings
            ],
            "relationships": [
                {
                    "type": r.relationship_type,
                    "confidence": r.confidence,
                    "metadata": r.metadata,
                }
                for r in correlation_result.relationships
            ],
            "process_contexts": {
                str(pid): {
                    "process_name": ctx.process_name,
                    "ppid": ctx.ppid,
                    "memory_regions_count": len(ctx.memory_regions),
                    "network_connections_count": len(ctx.network_connections),
                    "threads_count": len(ctx.threads),
                    "modules_count": len(ctx.modules),
                    "yara_matches_count": len(ctx.signature_matches),
                    "has_command_line": ctx.command_line is not None,
                }
                for pid, ctx in correlation_result.process_contexts.items()
            },
        }
        json.dump(results, f, indent=2, default=str)

    # 3. Findings by Severity
    severity_path = output_dir / "findings_by_severity.txt"
    with severity_path.open("w", encoding="utf-8") as f:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        findings_by_severity = {}

        for finding in correlation_result.findings:
            severity = finding.severity
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)

        f.write("FINDINGS GROUPED BY SEVERITY\n")
        f.write("=" * 80 + "\n\n")

        for severity in severity_order:
            if severity in findings_by_severity:
                f.write(f"{severity} SEVERITY ({len(findings_by_severity[severity])} findings):\n")
                f.write("-" * 80 + "\n")
                for finding in findings_by_severity[severity]:
                    f.write(f"  - {finding.title}\n")
                    f.write(f"    Rule: {finding.rule_id}\n")
                    f.write(f"    Confidence: {finding.confidence:.2f}\n")
                    f.write(f"    Description: {finding.description}\n")
                f.write("\n")

    # 4. Process Risk Assessment
    risk_path = output_dir / "process_risk_assessment.txt"
    with risk_path.open("w", encoding="utf-8") as f:
        f.write("PROCESS RISK ASSESSMENT\n")
        f.write("=" * 80 + "\n\n")

        for pid, context in correlation_result.process_contexts.items():
            # Count findings for this process
            process_findings = [
                f for f in correlation_result.findings
                if str(pid) in f.description or context.process_name in f.description
            ]

            # Calculate risk score based on findings
            risk_score = sum(f.confidence for f in process_findings)
            risk_level = "HIGH" if risk_score > 1.5 else "MEDIUM" if risk_score > 0.5 else "LOW"

            f.write(f"Process: {context.process_name} (PID: {pid})\n")
            f.write(f"Risk Level: {risk_level}\n")
            f.write(f"Risk Score: {risk_score:.2f}\n")
            f.write(f"Associated Findings: {len(process_findings)}\n")

            if process_findings:
                f.write("Triggered Rules:\n")
                for finding in process_findings:
                    f.write(f"  - {finding.rule_id}: {finding.title}\n")
            else:
                f.write("No findings triggered for this process\n")

            f.write("Indicators:\n")
            f.write(f"  - Executable Private Memory: {len(context.memory_regions)} regions\n")
            f.write(f"  - Network Connections: {len(context.network_connections)} connections\n")
            f.write(f"  - YARA Matches: {len(context.signature_matches)} matches\n")
            f.write(f"  - Unbacked Modules: {len([m for m in context.modules if m.original_data.get('path') is None])}\n")
            f.write(f"  - Suspicious Command Line: {'Yes' if context.command_line else 'No'}\n")

            f.write("\n" + "-" * 80 + "\n\n")

    print(f"Printable reports generated in: {output_dir}")
    print(f"  - {summary_path.name} (Human-readable summary)")
    print(f"  - {json_path.name} (Machine-readable JSON)")
    print(f"  - {severity_path.name} (Findings by severity)")
    print(f"  - {risk_path.name} (Process risk assessment)")


def run_end_to_end_test() -> None:
    """Run the end-to-end correlation test."""
    print("Running MemSentry Correlation Engine End-to-End Test")
    print("=" * 80)

    # Setup
    analysis_run_id = uuid4()
    output_dir = Path("tests/correlation/test_output")

    # Create correlation engine
    engine = CorrelationEngine(os_type="windows")
    print(f"Correlation Engine initialized with {len(engine.rules)} rules")

    # Create mock artifacts
    print("\nCreating mock artifacts simulating Volatility plugin output...")
    artifacts = create_mock_artifacts(analysis_run_id)
    print(f"Created {len(artifacts)} mock artifacts")

    # Run correlation
    print("\nRunning correlation analysis...")
    correlation_result = engine.correlate(artifacts, analysis_run_id)

    # Display summary
    print("\nCorrelation Analysis Complete:")
    print(f"  Total Findings: {len(correlation_result.findings)}")
    print(f"  Total Relationships: {len(correlation_result.relationships)}")
    print(f"  Total Processes Analyzed: {len(correlation_result.process_contexts)}")

    if correlation_result.findings:
        print("\nFindings Summary:")
        for finding in correlation_result.findings:
            print(f"  - [{finding.severity}] {finding.rule_id}: {finding.title}")

    # Generate printable reports
    print("\nGenerating printable reports...")
    generate_printable_report(correlation_result, output_dir, analysis_run_id)

    print("\n" + "=" * 80)
    print("End-to-End Test Complete!")
    print(f"Review the generated files in: {output_dir.absolute()}")


if __name__ == "__main__":
    run_end_to_end_test()
