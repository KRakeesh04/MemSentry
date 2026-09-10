"""Artifact Service providing structured view models for persisted Volatility artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository


@dataclass
class ProcessItemViewModel:
    """View model representing a process artifact correlated with its associated telemetry."""

    pid: int
    name: str
    ppid: int | None = None
    user: str = "N/A"
    session: int | str | None = None
    threads: int | str = 0
    handles: int | str = 0
    created_at: str = "N/A"
    command_line: str = "N/A"
    path: str = "N/A"
    is_suspicious: bool = False
    threat_description: str = ""
    threat_score: int | None = None
    sockets: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    memory_regions: list[str] = field(default_factory=list)
    provenance_plugin: str = "windows.pslist"
    analysis_run_id: UUID | None = None


class ArtifactService:
    """Service layer retrieving and correlating persisted Volatility artifacts for GUI presentation."""

    def __init__(
        self,
        artifact_repository: ArtifactRepository,
        analysis_run_repository: AnalysisRunRepository | None = None,
    ) -> None:
        self.artifact_repository = artifact_repository
        self.analysis_run_repository = analysis_run_repository

    def get_latest_analysis_run_for_evidence(self, evidence_id: UUID) -> UUID | None:
        """Fetch the ID of the most recent analysis run for an evidence file, if any."""
        if self.analysis_run_repository is None:
            return None
        try:
            runs = self.analysis_run_repository.list_by_evidence(evidence_id)
            if not runs:
                return None
            # Return latest run created
            sorted_runs = sorted(runs, key=lambda r: r.created_at, reverse=True)
            return sorted_runs[0].id
        except Exception:
            return None

    def get_processes_for_analysis_run(self, analysis_run_id: UUID) -> list[ProcessItemViewModel]:
        """Fetch process, cmdline, malfind, netscan, and dlllist artifacts for an analysis run."""
        try:
            proc_artifacts = self.artifact_repository.list_by_type(analysis_run_id, "process")
            cmd_artifacts = self.artifact_repository.list_by_type(analysis_run_id, "command_line")
            malfind_artifacts = self.artifact_repository.list_by_type(analysis_run_id, "memory_region")
            net_artifacts = self.artifact_repository.list_by_type(analysis_run_id, "network_connection")
            dll_artifacts = self.artifact_repository.list_by_type(analysis_run_id, "module")
        except Exception:
            return []

        # Map command lines by PID
        cmd_map: dict[int, str] = {}
        for c in cmd_artifacts:
            raw_pid = c.pid if c.pid is not None else c.original_data.get("pid", c.original_data.get("PID"))
            if raw_pid is not None:
                try:
                    c_pid = int(raw_pid)
                except (ValueError, TypeError):
                    continue
                cmd_val = (
                    c.original_data.get("command_line")
                    or c.original_data.get("args")
                    or c.original_data.get("Args")
                    or c.original_data.get("CommandLine")
                    or "N/A"
                )
                cmd_map[c_pid] = str(cmd_val)

        # Map malfind (memory regions) by PID
        malfind_map: dict[int, list[str]] = {}
        for m in malfind_artifacts:
            raw_pid = m.pid if m.pid is not None else m.original_data.get("pid", m.original_data.get("PID"))
            if raw_pid is not None:
                try:
                    m_pid = int(raw_pid)
                except (ValueError, TypeError):
                    continue
                region_info = (
                    m.original_data.get("protection")
                    or m.original_data.get("Protection")
                    or m.original_data.get("details")
                    or "Injected Memory Region"
                )
                malfind_map.setdefault(m_pid, []).append(str(region_info))

        # Map network connections by PID
        net_map: dict[int, list[str]] = {}
        for n in net_artifacts:
            raw_pid = n.pid if n.pid is not None else n.original_data.get("pid", n.original_data.get("PID"))
            if raw_pid is not None:
                try:
                    n_pid = int(raw_pid)
                except (ValueError, TypeError):
                    continue
                local_addr = n.original_data.get("local_addr") or n.original_data.get("LocalAddr") or n.original_data.get("src_ip", "")
                foreign_addr = n.original_data.get("foreign_addr") or n.original_data.get("ForeignAddr") or n.original_data.get("dest_ip", "")
                state = n.original_data.get("state") or n.original_data.get("State", "ESTABLISHED")
                sock_info = f"{local_addr} -> {foreign_addr} ({state})" if local_addr or foreign_addr else "Active Socket"
                net_map.setdefault(n_pid, []).append(sock_info)

        # Map modules by PID
        dll_map: dict[int, list[str]] = {}
        for d in dll_artifacts:
            raw_pid = d.pid if d.pid is not None else d.original_data.get("pid", d.original_data.get("PID"))
            if raw_pid is not None:
                try:
                    d_pid = int(raw_pid)
                except (ValueError, TypeError):
                    continue
                mod_name = d.original_data.get("path") or d.original_data.get("Path") or d.original_data.get("name") or "Module"
                dll_map.setdefault(d_pid, []).append(str(mod_name))

        view_models: list[ProcessItemViewModel] = []
        for p in proc_artifacts:
            data = p.original_data
            pid_val = p.pid if p.pid is not None else data.get("pid", data.get("PID", 0))
            try:
                pid = int(pid_val)
            except (ValueError, TypeError):
                pid = 0

            ppid_val = data.get("ppid", data.get("PPID"))
            try:
                ppid = int(ppid_val) if ppid_val is not None else None
            except (ValueError, TypeError):
                ppid = None

            proc_name = (
                data.get("ImageFileName")
                or data.get("name")
                or data.get("process_name")
                or f"Process-{pid}"
            )
            user = data.get("user") or data.get("Owner") or "N/A"
            threads_val = data.get("threads") or data.get("NumThreads") or data.get("Threads")
            handles_val = data.get("handles") or data.get("NumHandles") or data.get("Handles")
            created = data.get("create_time") or data.get("CreateTime") or "N/A"
            path = data.get("path") or data.get("ImagePath") or "N/A"

            prov_plugin = p.provenance.get("plugin_name", "windows.pslist")
            is_linux = "linux" in prov_plugin.lower()

            handles_disp: int | str = (
                "Not Applicable" if is_linux or handles_val is None else (
                    int(handles_val) if str(handles_val).isdigit() else "Not Applicable"
                )
            )
            session_disp: int | str | None = (
                "Not Applicable" if is_linux and data.get("session") is None else data.get("session")
            )

            is_susp = pid in malfind_map or (
                pid in net_map and any("443" in s or "4444" in s for s in net_map[pid])
            )
            threat_desc = ""
            if pid in malfind_map:
                threat_desc += f"Injected RWX memory region detected ({len(malfind_map[pid])} region(s)). "
            if pid in net_map:
                threat_desc += f"Active network sockets ({len(net_map[pid])} connection(s))."

            score: int | None = None
            if pid in malfind_map:
                score = min(100, 85 + len(malfind_map[pid]) * 5)
            elif is_susp:
                score = 65
            else:
                score = 0

            vm = ProcessItemViewModel(
                pid=pid,
                name=str(proc_name),
                ppid=ppid,
                user=str(user),
                session=session_disp,
                threads=int(threads_val) if threads_val is not None and str(threads_val).isdigit() else 0,
                handles=handles_disp,
                created_at=str(created),
                command_line=cmd_map.get(pid, "N/A"),
                path=str(path),
                is_suspicious=is_susp,
                threat_description=threat_desc.strip(),
                threat_score=score,
                sockets=net_map.get(pid, []),
                modules=dll_map.get(pid, []),
                memory_regions=malfind_map.get(pid, []),
                provenance_plugin=prov_plugin,
                analysis_run_id=analysis_run_id,
            )
            view_models.append(vm)

        return view_models

    @staticmethod
    def filter_processes(
        vms: list[ProcessItemViewModel], query: str
    ) -> list[ProcessItemViewModel]:
        """Filter process view models by process name, PID, IP, plugin, artifact type, or severity keyword."""
        q = query.strip().lower()
        if not q:
            return vms

        filtered: list[ProcessItemViewModel] = []
        for vm in vms:
            matches_name = q in vm.name.lower()
            matches_pid = q in str(vm.pid) or (vm.ppid is not None and q in str(vm.ppid))
            matches_cmd = q in vm.command_line.lower() or q in vm.path.lower()
            matches_plugin = q in vm.provenance_plugin.lower()
            matches_ip = any(q in sock.lower() for sock in vm.sockets)
            matches_mod = any(q in mod.lower() for mod in vm.modules)
            matches_mem = any(q in mem.lower() for mem in vm.memory_regions)

            matches_sev = False
            if q in ("suspicious", "susp", "malicious", "threat", "rwx", "critical"):
                matches_sev = vm.is_suspicious or len(vm.memory_regions) > 0
            elif q in ("clean", "normal", "info"):
                matches_sev = not vm.is_suspicious

            if (
                matches_name
                or matches_pid
                or matches_cmd
                or matches_plugin
                or matches_ip
                or matches_mod
                or matches_mem
                or matches_sev
            ):
                filtered.append(vm)

        return filtered
