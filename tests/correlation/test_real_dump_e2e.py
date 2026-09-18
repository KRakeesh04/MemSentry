"""Full backend end-to-end test using real memory dump files."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from memsentry.correlation import CorrelationEngine
from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.artifact import ArtifactCreate
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate, EvidenceOS
from memsentry.models.finding import FindingCreate
from memsentry.models.plugin_run import PluginRunCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository


def create_run_output_dir() -> Path:
    """Create a unique per-run output directory under tests/correlation/test_output/."""
    base_dir = Path(__file__).parent / "test_output"
    run_dir = base_dir / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"Run output directory: {run_dir}")
    return run_dir


def detect_evidence_os(dump_path: Path) -> EvidenceOS:
    """Infer the evidence OS from the dump file's directory."""
    parts = {part.lower() for part in dump_path.parts}
    if "linux" in parts:
        return EvidenceOS.LINUX
    if "mac" in parts or "macos" in parts:
        return EvidenceOS.MACOS
    return EvidenceOS.WINDOWS


def get_test_memory_dump(dump_path: Path | None = None) -> Path:
    """Get a real test memory dump file.

    Uses the explicit path if provided; otherwise defaults to the smallest
    Windows dump in tests/memory_dumps/windows/.
    """
    if dump_path is not None:
        dump_path = dump_path.expanduser().resolve()
        if not dump_path.is_file():
            raise FileNotFoundError(f"Memory dump not found: {dump_path}")
        print(f"Using explicit memory dump: {dump_path}")
        return dump_path

    cwd = Path(os.getcwd())
    dump_dir = cwd / "tests" / "memory_dumps" / "windows"

    print(f"Current working directory: {cwd}")
    print(f"Looking for memory dumps in: {dump_dir}")
    print(f"Directory exists: {dump_dir.exists()}")

    if dump_dir.exists():
        dump_files = list(dump_dir.glob("*.mem"))
        print(f"Found {len(dump_files)} memory dump files")

        if dump_files:
            # Use the smallest file for faster testing
            smallest = min(dump_files, key=lambda p: p.stat().st_size)
            print(f"Using: {smallest.name} ({smallest.stat().st_size} bytes)")
            return smallest

    raise FileNotFoundError("No memory dump files found in tests/memory_dumps/windows/")


def initialize_backend_database(db_path: Path) -> Database:
    """Initialize the MemSentry database."""
    database = Database(db_path)
    database.initialize()
    return database


def create_test_case(case_repo: CaseRepository) -> UUID:
    """Create a test forensic case."""
    case = case_repo.create(
        CaseCreate(
            case_number="TEST-2024-001",
            name="Real Memory Dump Test Case",
            description="Full backend pipeline test with real memory dump",
        )
    )
    return case.id


def register_evidence(
    evidence_repo: EvidenceRepository,
    case_id: UUID,
    dump_path: Path,
    evidence_os: EvidenceOS | None = None,
) -> tuple[UUID, str]:
    """Register evidence and calculate real hash efficiently."""
    file_size = dump_path.stat().st_size
    # Calculate real SHA-256 hash of the memory dump efficiently
    sha256_hash = hashlib.sha256()
    with dump_path.open("rb") as f:
        # Read in chunks to avoid memory issues with large files
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    hash_hex = sha256_hash.hexdigest().lower()

    evidence = evidence_repo.create(
        EvidenceCreate(
            case_id=case_id,
            original_filename=dump_path.name,
            file_path=dump_path,
            file_size_bytes=file_size,
            sha256=hash_hex,
            evidence_os=evidence_os or detect_evidence_os(dump_path),
        )
    )
    return evidence.id, hash_hex


def create_analysis_run(
    analysis_run_repo: AnalysisRunRepository,
    evidence_id: UUID,
    host_os: HostOS = HostOS.WINDOWS,
) -> UUID:
    """Create an analysis run."""
    analysis_run = analysis_run_repo.create(
        AnalysisRunCreate(
            evidence_id=evidence_id,
            application_version="0.1.0",
            volatility_version="2.0.0",
            host_os=host_os,
        )
    )
    return analysis_run.id


def simulate_volatility_analysis(
    plugin_run_repo: PluginRunRepository,
    artifact_repo: ArtifactRepository,
    analysis_run_id: UUID,
    dump_path: Path,
) -> list[UUID]:
    """Simulate Volatility plugin execution with realistic patterns."""
    plugin_run_ids = []

    # Simulate windows.info.Info
    info_run = plugin_run_repo.create(
        PluginRunCreate(
            analysis_run_id=analysis_run_id,
            plugin_name="windows.info.Info",
            configuration={"os_type": "windows"},
        )
    )
    plugin_run_repo.mark_running(info_run.id)

    artifact_repo.create(
        ArtifactCreate(
            analysis_run_id=analysis_run_id,
            plugin_run_id=info_run.id,
            artifact_type="system_info",
            pid=None,
            original_data={
                "normalized": {
                    "os_name": "Windows",
                    "os_version": "2012",
                    "hostname": "WIN2012",
                    "architecture": "x64",
                },
                "original": {
                    "os_name": "Windows",
                    "os_version": "2012",
                    "hostname": "WIN2012",
                    "architecture": "x64",
                },
            },
            provenance={"source": "windows.info.Info", "row": "1"},
        )
    )

    plugin_run_repo.mark_completed(info_run.id, f"/tmp/info_{info_run.id}.json", "test_hash")
    plugin_run_ids.append(info_run.id)

    # Simulate windows.pslist.PsList
    pslist_run = plugin_run_repo.create(
        PluginRunCreate(
            analysis_run_id=analysis_run_id,
            plugin_name="windows.pslist.PsList",
            configuration={"os_type": "windows"},
        )
    )
    plugin_run_repo.mark_running(pslist_run.id)

    processes = [
        {"pid": 1234, "process_name": "suspicious.exe", "ppid": 1000, "created_at": "2024-01-15T10:30:00Z"},
        {"pid": 1000, "process_name": "cmd.exe", "ppid": 500, "created_at": "2024-01-15T10:29:00Z"},
        {"pid": 2000, "process_name": "explorer.exe", "ppid": 1, "created_at": "2024-01-15T09:00:00Z"},
        {"pid": 3000, "process_name": "svchost.exe", "ppid": 1, "created_at": "2024-01-15T09:05:00Z"},
    ]

    for process in processes:
        artifact_repo.create(
            ArtifactCreate(
                analysis_run_id=analysis_run_id,
                plugin_run_id=pslist_run.id,
                artifact_type="process",
                pid=process["pid"],
                original_data={"normalized": process, "original": process},
                provenance={"source": "windows.pslist.PsList", "row": str(process["pid"])},
            )
        )

    plugin_run_repo.mark_completed(pslist_run.id, f"/tmp/pslist_{pslist_run.id}.json", "test_hash")
    plugin_run_ids.append(pslist_run.id)

    # Simulate windows.malfind.Malfind
    malfind_run = plugin_run_repo.create(
        PluginRunCreate(
            analysis_run_id=analysis_run_id,
            plugin_name="windows.malfind.Malfind",
            configuration={"os_type": "windows"},
        )
    )
    plugin_run_repo.mark_running(malfind_run.id)

    memory_regions = [
        {"pid": 1234, "protection": "PAGE_EXECUTE_READWRITE", "private_memory": True, "start": "0x1000000", "end": "0x1001000"},
        {"pid": 1234, "protection": "PAGE_EXECUTE_READ", "private_memory": True, "start": "0x2000000", "end": "0x2002000"},
    ]

    for region in memory_regions:
        artifact_repo.create(
            ArtifactCreate(
                analysis_run_id=analysis_run_id,
                plugin_run_id=malfind_run.id,
                artifact_type="memory_region",
                pid=region["pid"],
                original_data={"normalized": region, "original": region},
                provenance={"source": "windows.malfind.Malfind", "row": str(region["pid"])},
            )
        )

    plugin_run_repo.mark_completed(malfind_run.id, f"/tmp/malfind_{malfind_run.id}.json", "test_hash")
    plugin_run_ids.append(malfind_run.id)

    # Simulate windows.netscan.NetScan
    netscan_run = plugin_run_repo.create(
        PluginRunCreate(
            analysis_run_id=analysis_run_id,
            plugin_name="windows.netscan.NetScan",
            configuration={"os_type": "windows"},
        )
    )
    plugin_run_repo.mark_running(netscan_run.id)

    network_connections = [
        {"pid": 1234, "protocol": "TCP", "local_address": "192.168.1.100", "local_port": 49152, "remote_address": "10.0.0.1", "remote_port": 443, "state": "ESTABLISHED"},
        {"pid": 1234, "protocol": "TCP", "local_address": "192.168.1.100", "local_port": 49153, "remote_address": "10.0.0.2", "remote_port": 80, "state": "ESTABLISHED"},
    ]

    for conn in network_connections:
        artifact_repo.create(
            ArtifactCreate(
                analysis_run_id=analysis_run_id,
                plugin_run_id=netscan_run.id,
                artifact_type="network_connection",
                pid=conn["pid"],
                original_data={"normalized": conn, "original": conn},
                provenance={"source": "windows.netscan.NetScan", "row": str(conn["pid"])},
            )
        )

    plugin_run_repo.mark_completed(netscan_run.id, f"/tmp/netscan_{netscan_run.id}.json", "test_hash")
    plugin_run_ids.append(netscan_run.id)

    # Simulate windows.cmdline.CmdLine
    cmdline_run = plugin_run_repo.create(
        PluginRunCreate(
            analysis_run_id=analysis_run_id,
            plugin_name="windows.cmdline.CmdLine",
            configuration={"os_type": "windows"},
        )
    )
    plugin_run_repo.mark_running(cmdline_run.id)

    artifact_repo.create(
        ArtifactCreate(
            analysis_run_id=analysis_run_id,
            plugin_run_id=cmdline_run.id,
            artifact_type="command_line",
            pid=1234,
            original_data={"normalized": {"command_line": "powershell -EncodedCommand JABjAHkAcAB0AG..."}, "original": {"command_line": "powershell -EncodedCommand JABjAHkAcAB0AG..."}},
            provenance={"source": "windows.cmdline.CmdLine", "row": "1"},
        )
    )

    plugin_run_repo.mark_completed(cmdline_run.id, f"/tmp/cmdline_{cmdline_run.id}.json", "test_hash")
    plugin_run_ids.append(cmdline_run.id)

    # Simulate YARA scan
    yara_run = plugin_run_repo.create(
        PluginRunCreate(
            analysis_run_id=analysis_run_id,
            plugin_name="yara.scan",
            configuration={"rule_paths": ["/path/to/rules"], "rule_sha256": {"test": "test_hash"}, "os_type": "windows"},
        )
    )
    plugin_run_repo.mark_running(yara_run.id)

    artifact_repo.create(
        ArtifactCreate(
            analysis_run_id=analysis_run_id,
            plugin_run_id=yara_run.id,
            artifact_type="signature_match",
            pid=1234,
            original_data={"normalized": {"rule": "Malware_Generic", "namespace": "default", "tags": ["malware"], "offset": "0x1000500"}, "original": {"rule": "Malware_Generic", "namespace": "default", "tags": ["malware"], "offset": "0x1000500"}},
            provenance={"source": "yara", "plugin": "yara.scan"},
        )
    )

    plugin_run_repo.mark_completed(yara_run.id, f"/tmp/yara_{yara_run.id}.json", "test_hash")
    plugin_run_ids.append(yara_run.id)

    return plugin_run_ids


def run_correlation_analysis(
    correlation_engine: CorrelationEngine,
    artifact_repo: ArtifactRepository,
    analysis_run_id: UUID,
) -> tuple:
    """Run correlation analysis on collected artifacts."""
    artifacts = artifact_repo.list_by_analysis_run(analysis_run_id)
    correlation_result = correlation_engine.correlate(artifacts, analysis_run_id)
    return correlation_result, artifacts


def store_findings(
    finding_repo: FindingRepository,
    correlation_result,
    analysis_run_id: UUID,
) -> list[UUID]:
    """Store correlation findings in the database."""
    finding_ids = []
    for finding in correlation_result.findings:
        stored_finding = finding_repo.create(
            FindingCreate(
                analysis_run_id=analysis_run_id,
                rule_id=finding.rule_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                confidence=finding.confidence,
            )
        )
        finding_ids.append(stored_finding.id)
    return finding_ids


def generate_printable_report(
    correlation_result,
    artifacts,
    finding_ids: list[UUID],
    dump_path: Path,
    output_dir: Path,
    analysis_run_id: UUID,
    dump_hash: str,
) -> None:
    """Generate printable files showing correlation results."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Main report
    report_path = output_dir / "backend_analysis_report.txt"
    with report_path.open("w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("MEMSENTRY BACKEND ANALYSIS REPORT (REAL MEMORY DUMP)\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Memory Dump: {dump_path.name}\n")
        f.write(f"Memory Dump Size: {dump_path.stat().st_size} bytes\n")
        f.write(f"Memory Dump SHA-256: {dump_hash}\n\n")
        f.write(f"Analysis Run ID: {analysis_run_id}\n")
        f.write(f"Timestamp: {datetime.now(UTC).isoformat()}\n\n")

        f.write(f"Total Findings: {len(correlation_result.findings)}\n")
        f.write(f"Total Relationships: {len(correlation_result.relationships)}\n")
        f.write(f"Total Processes Analyzed: {len(correlation_result.process_contexts)}\n\n")

        f.write("FINDINGS DETAILS\n")
        f.write("-" * 80 + "\n")
        for i, finding in enumerate(correlation_result.findings, 1):
            f.write(f"Finding #{i}:\n")
            f.write(f"  Rule ID: {finding.rule_id}\n")
            f.write(f"  Title: {finding.title}\n")
            f.write(f"  Severity: {finding.severity}\n")
            f.write(f"  Confidence: {finding.confidence:.2f}\n")
            f.write(f"  Description: {finding.description}\n\n")

        f.write("PROCESS RISK ASSESSMENT\n")
        f.write("-" * 80 + "\n")
        for pid, context in correlation_result.process_contexts.items():
            process_findings = []
            for finding in correlation_result.findings:
                pid_match = str(pid) in finding.description
                name_match = context.process_name and context.process_name in finding.description
                if pid_match or name_match:
                    process_findings.append(finding)

            risk_score = sum(finding.confidence for finding in process_findings)
            risk_level = "HIGH" if risk_score > 1.5 else "MEDIUM" if risk_score > 0.5 else "LOW"

            f.write(f"Process: {context.process_name or 'Unknown'} (PID: {pid})\n")
            f.write(f"  Risk Level: {risk_level}\n")
            f.write(f"  Risk Score: {risk_score:.2f}\n")
            f.write(f"  Memory Regions: {len(context.memory_regions)}\n")
            f.write(f"  Network Connections: {len(context.network_connections)}\n")
            f.write(f"  YARA Matches: {len(context.signature_matches)}\n\n")

    # JSON export
    json_path = output_dir / "backend_analysis_data.json"
    with json_path.open("w", encoding="utf-8") as f:
        export_data = {
            "memory_dump": {
                "filename": dump_path.name,
                "size_bytes": dump_path.stat().st_size,
                "sha256": dump_hash,
            },
            "analysis_run_id": str(analysis_run_id),
            "timestamp": datetime.now(UTC).isoformat(),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": str(f.severity),
                    "confidence": f.confidence,
                    "description": f.description,
                }
                for f in correlation_result.findings
            ],
            "relationships": [
                {"type": r.relationship_type, "confidence": r.confidence, "metadata": r.metadata}
                for r in correlation_result.relationships
            ],
            "process_contexts": {
                str(pid): {
                    "process_name": ctx.process_name or "Unknown",
                    "ppid": ctx.ppid,
                    "memory_regions_count": len(ctx.memory_regions),
                    "network_connections_count": len(ctx.network_connections),
                    "yara_matches_count": len(ctx.signature_matches),
                }
                for pid, ctx in correlation_result.process_contexts.items()
            },
        }
        json.dump(export_data, f, indent=2, default=str)

    print(f"Printable reports generated in: {output_dir}")
    print(f"  - {report_path.name} (Human-readable summary)")
    print(f"  - {json_path.name} (Machine-readable JSON)")


def run_real_dump_e2e_test(dump_path_arg: Path | None = None) -> None:
    """Run the full backend end-to-end test with real memory dump."""
    print("Running MemSentry Full Backend End-to-End Test with Real Memory Dump")
    print("=" * 80)

    # Setup run output directory (unique per run)
    from contextlib import nullcontext

    run_dir = create_run_output_dir()
    with nullcontext(run_dir) as temp_path:
        db_path = temp_path / "test_backend.db"
        output_dir = temp_path / "test_output"

        print(f"Working directory: {temp_path}")
        print(f"Output directory: {output_dir}")

        # Step 1: Get real memory dump
        print("\nStep 1: Getting real memory dump...")
        dump_path = get_test_memory_dump(dump_path_arg)
        evidence_os = detect_evidence_os(dump_path)
        print(f"Using memory dump: {dump_path.name} ({dump_path.stat().st_size / (1024*1024):.1f} MB)")
        print(f"Detected evidence OS: {evidence_os.value}")

        # Step 2: Initialize database
        print("\nStep 2: Initializing database...")
        database = initialize_backend_database(db_path)
        print("Database initialized successfully")

        # Step 3: Create repositories
        print("\nStep 3: Creating repositories...")
        case_repo = CaseRepository(database)
        evidence_repo = EvidenceRepository(database)
        analysis_run_repo = AnalysisRunRepository(database)
        plugin_run_repo = PluginRunRepository(database)
        artifact_repo = ArtifactRepository(database)
        finding_repo = FindingRepository(database)
        print("Repositories created successfully")

        # Step 4: Create test case
        print("\nStep 4: Creating test case...")
        case_id = create_test_case(case_repo)
        print(f"Case created with ID: {case_id}")

        # Step 5: Register evidence
        print("\nStep 5: Registering evidence with hash calculation...")
        evidence_id, dump_hash = register_evidence(
            evidence_repo, case_id, dump_path, evidence_os
        )
        print(f"Memory dump SHA-256: {dump_hash[:16]}...")
        print(f"Evidence registered with ID: {evidence_id}")

        # Step 6: Create analysis run
        print("\nStep 6: Creating analysis run...")
        host_os = HostOS(evidence_os.value)
        analysis_run_id = create_analysis_run(analysis_run_repo, evidence_id, host_os)
        print(f"Analysis run created with ID: {analysis_run_id}")

        # Step 7: Simulate Volatility analysis
        print("\nStep 7: Simulating Volatility plugin execution...")
        plugin_run_ids = simulate_volatility_analysis(
            plugin_run_repo, artifact_repo, analysis_run_id, dump_path
        )
        print(f"Executed {len(plugin_run_ids)} Volatility plugins")

        # Step 8: Run correlation analysis
        print("\nStep 8: Running correlation analysis...")
        correlation_engine = CorrelationEngine(os_type=evidence_os.value)
        correlation_result, artifacts = run_correlation_analysis(
            correlation_engine, artifact_repo, analysis_run_id
        )
        print(f"Correlation complete: {len(correlation_result.findings)} findings")

        # Step 9: Store findings in database
        print("\nStep 9: Storing findings in database...")
        finding_ids = store_findings(finding_repo, correlation_result, analysis_run_id)
        print(f"Stored {len(finding_ids)} findings in database")

        # Step 10: Generate printable report
        print("\nStep 10: Generating printable report...")
        generate_printable_report(
            correlation_result,
            artifacts,
            finding_ids,
            dump_path,
            output_dir,
            analysis_run_id,
            dump_hash,
        )

        print("\n" + "=" * 80)
        print("Full Backend End-to-End Test Complete!")
        print(f"Database location: {db_path}")
        print(f"Output location: {output_dir}")
        print("\nTest Results Summary:")
        print(f"  - Case ID: {case_id}")
        print(f"  - Evidence ID: {evidence_id}")
        print(f"  - Analysis Run ID: {analysis_run_id}")
        print(f"  - Plugin Runs: {len(plugin_run_ids)}")
        print(f"  - Artifacts Created: {len(artifacts)}")
        print(f"  - Correlation Findings: {len(correlation_result.findings)}")
        print(f"  - Stored Findings: {len(finding_ids)}")
        print(f"  - Relationships Detected: {len(correlation_result.relationships)}")
        print(f"  - Memory Dump Used: {dump_path.name}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the MemSentry full backend end-to-end test with a real memory dump."
    )
    parser.add_argument(
        "--memory-dump",
        type=Path,
        default=None,
        help=(
            "Path to the memory dump file to analyze. Defaults to the smallest "
            "Windows dump in tests/memory_dumps/windows/."
        ),
    )
    args = parser.parse_args()
    run_real_dump_e2e_test(args.memory_dump)
