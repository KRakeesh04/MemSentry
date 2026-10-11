"""Graph builder service transforming case forensic records into GraphData."""

from __future__ import annotations

import logging
from pathlib import Path
from uuid import UUID

from memsentry.app.case_service import workspace_database
from memsentry.graph.models import GraphData, GraphEdge, GraphNode
from memsentry.models.case import Case
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_evidence_repository import FindingEvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Constructs GraphData from stored evidence, artifacts, and findings."""

    @classmethod
    def build_for_case(cls, workspace_path: str | Path, case: Case) -> GraphData:
        database = workspace_database(Path(workspace_path))
        graph = GraphData()

        # Repositories
        evidence_repo = EvidenceRepository(database)
        analysis_run_repo = AnalysisRunRepository(database)
        artifact_repo = ArtifactRepository(database)
        finding_repo = FindingRepository(database)
        finding_ev_repo = FindingEvidenceRepository(database)

        # 1. Fetch evidence
        evidence_list = evidence_repo.list_by_case(case.id)
        if not evidence_list:
            return graph

        # Track mappings: (analysis_run_id, pid) -> node_id
        # Also artifact_id -> node_id
        proc_node_by_run_pid: dict[tuple[UUID, int], str] = {}
        node_by_artifact_id: dict[str, str] = {}
        # Also map pid -> list of proc node IDs across run if needed
        proc_nodes_by_pid: dict[int, list[str]] = {}

        for ev in evidence_list:
            ev_node_id = f"ev:{ev.id}"
            graph.add_node(
                GraphNode(
                    id=ev_node_id,
                    node_type="evidence",
                    label=ev.original_filename,
                    subtitle=f"{ev.evidence_os.value.upper() if ev.evidence_os else 'UNKNOWN OS'}",
                    metadata={
                        "evidence_id": str(ev.id),
                        "filename": ev.original_filename,
                        "sha256": ev.sha256,
                        "size_bytes": ev.file_size_bytes,
                        "operating_system": ev.evidence_os.value if ev.evidence_os else "unknown",
                        "status": ev.integrity_status.value if hasattr(ev.integrity_status, "value") else str(ev.integrity_status),
                    },
                )
            )

            runs = analysis_run_repo.list_by_evidence(ev.id)
            for run in runs:
                # 2. Fetch artifacts for run
                artifacts = artifact_repo.list_by_analysis_run(run.id)

                # Collect process artifacts first
                process_artifacts = [
                    a for a in artifacts if a.artifact_type in ("process", "process_tree")
                ]

                # Map ppid per process
                proc_ppid_map: dict[str, int | None] = {}

                for pa in process_artifacts:
                    data = pa.original_data or {}
                    norm = data.get("normalized", data) if isinstance(data, dict) else {}
                    pid = pa.pid if pa.pid is not None else norm.get("pid")
                    if pid is None or pid < 0:
                        continue

                    proc_node_id = f"proc:{run.id}:{pid}"
                    proc_name = (
                        norm.get("process_name")
                        or norm.get("ImageFileName")
                        or f"PID {pid}"
                    )
                    ppid = norm.get("ppid")

                    if proc_node_id not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=proc_node_id,
                                node_type="process",
                                label=proc_name,
                                subtitle=f"PID {pid}",
                                metadata={
                                    "pid": pid,
                                    "ppid": ppid,
                                    "process_name": proc_name,
                                    "analysis_run_id": str(run.id),
                                    "evidence_name": ev.original_filename,
                                    "created_at": norm.get("created_at"),
                                    "exited_at": norm.get("exited_at"),
                                    "cmdline": norm.get("cmdline") or norm.get("command"),
                                },
                            )
                        )
                        proc_node_by_run_pid[(run.id, pid)] = proc_node_id
                        proc_nodes_by_pid.setdefault(pid, []).append(proc_node_id)
                        proc_ppid_map[proc_node_id] = ppid
                        # Edge: evidence -> process
                        graph.add_edge(
                            GraphEdge(
                                source_id=ev_node_id,
                                target_id=proc_node_id,
                                label="contains",
                                relationship_type="contains_process",
                            )
                        )

                    node_by_artifact_id[str(pa.id)] = proc_node_id

                # Link process -> process (parent-child)
                for proc_node_id, ppid in proc_ppid_map.items():
                    if ppid is not None and (run.id, ppid) in proc_node_by_run_pid:
                        parent_node_id = proc_node_by_run_pid[(run.id, ppid)]
                        if parent_node_id != proc_node_id:
                            graph.add_edge(
                                GraphEdge(
                                    source_id=parent_node_id,
                                    target_id=proc_node_id,
                                    label="spawned",
                                    relationship_type="parent_of",
                                )
                            )

                # 3. Process network connections
                net_artifacts = [
                    a for a in artifacts if a.artifact_type == "network_connection"
                ]
                seen_endpoints: set[str] = set()

                for na in net_artifacts:
                    data = na.original_data or {}
                    norm = data.get("normalized", data) if isinstance(data, dict) else {}
                    local_addr = norm.get("local_address", "")
                    local_port = norm.get("local_port", "")
                    remote_addr = norm.get("remote_address") or norm.get("foreign_address", "")
                    remote_port = norm.get("remote_port") or norm.get("foreign_port", "")
                    proto = (norm.get("protocol") or "TCP").upper()
                    state = norm.get("state") or ""
                    pid = na.pid if na.pid is not None else norm.get("pid")

                    endpoint_str = f"{remote_addr}:{remote_port}" if remote_addr else f"{local_addr}:{local_port}"
                    if not endpoint_str or endpoint_str == ":":
                        endpoint_str = f"Net-{na.id}"

                    net_node_id = f"net:{run.id}:{endpoint_str}"
                    if net_node_id not in seen_endpoints:
                        seen_endpoints.add(net_node_id)
                        graph.add_node(
                            GraphNode(
                                id=net_node_id,
                                node_type="network",
                                label=endpoint_str,
                                subtitle=f"{proto} · {state or 'ENDPOINT'}",
                                metadata={
                                    "protocol": proto,
                                    "local_address": local_addr,
                                    "local_port": local_port,
                                    "remote_address": remote_addr,
                                    "remote_port": remote_port,
                                    "state": state,
                                    "pid": pid,
                                },
                            )
                        )
                        node_by_artifact_id[str(na.id)] = net_node_id

                    # Edge: process -> network
                    if pid is not None and (run.id, pid) in proc_node_by_run_pid:
                        proc_node_id = proc_node_by_run_pid[(run.id, pid)]
                        graph.add_edge(
                            GraphEdge(
                                source_id=proc_node_id,
                                target_id=net_node_id,
                                label="connected",
                                relationship_type="network_traffic",
                            )
                        )

                # 4. Fetch findings
                findings = finding_repo.list_by_analysis_run(run.id)
                for f in findings:
                    finding_node_id = f"find:{f.id}"
                    graph.add_node(
                        GraphNode(
                            id=finding_node_id,
                            node_type="finding",
                            label=f.title,
                            subtitle=f.severity.value.upper(),
                            metadata={
                                "finding_id": str(f.id),
                                "title": f.title,
                                "description": f.description,
                                "severity": f.severity.value,
                                "rule_id": f.rule_id,
                                "confidence": f.confidence,
                            },
                        )
                    )

                    # Link finding -> process via FindingEvidence
                    ev_items = finding_ev_repo.list_by_finding(f.id)
                    linked_proc = False
                    for fe in ev_items:
                        # Case 1: source_reference is artifact_id
                        if fe.source_reference and fe.source_reference in node_by_artifact_id:
                            target_id = node_by_artifact_id[fe.source_reference]
                            graph.add_edge(
                                GraphEdge(
                                    source_id=finding_node_id,
                                    target_id=target_id,
                                    label="flagged",
                                    relationship_type="flagged_process",
                                )
                            )
                            linked_proc = True
                        # Case 2: supporting_data has pid
                        elif fe.supporting_data and "pid" in fe.supporting_data:
                            spid = fe.supporting_data["pid"]
                            if spid is not None and (run.id, spid) in proc_node_by_run_pid:
                                target_id = proc_node_by_run_pid[(run.id, spid)]
                                graph.add_edge(
                                    GraphEdge(
                                        source_id=finding_node_id,
                                        target_id=target_id,
                                        label="flagged",
                                        relationship_type="flagged_process",
                                    )
                                )
                                linked_proc = True

                    # If finding could not be linked to a specific process, link to evidence
                    if not linked_proc:
                        graph.add_edge(
                            GraphEdge(
                                source_id=ev_node_id,
                                target_id=finding_node_id,
                                label="alert",
                                relationship_type="finding_alert",
                            )
                        )

        return graph
