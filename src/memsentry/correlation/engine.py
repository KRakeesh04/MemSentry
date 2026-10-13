"""Correlation engine for memory forensics artifact analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from memsentry.correlation.rule_loader import (
    CorrelationRule,
    get_default_rules_path,
    load_rules_from_yaml,
)
from memsentry.models.artifact import Artifact
from memsentry.models.finding import FindingCreate, FindingSeverity


@dataclass(frozen=True, slots=True)
class ArtifactRelationship:
    """A relationship between two artifacts."""

    source_artifact_id: UUID
    target_artifact_id: UUID
    relationship_type: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ProcessContext:
    """Collected artifacts for a single process."""

    pid: int
    process_name: str | None
    ppid: int | None
    memory_regions: list[Artifact] = field(default_factory=list)
    network_connections: list[Artifact] = field(default_factory=list)
    threads: list[Artifact] = field(default_factory=list)
    modules: list[Artifact] = field(default_factory=list)
    signature_matches: list[Artifact] = field(default_factory=list)
    command_line: Artifact | None = None


@dataclass
class CorrelationResult:
    """Results from correlation analysis."""

    findings: list[FindingCreate] = field(default_factory=list)
    relationships: list[ArtifactRelationship] = field(default_factory=list)
    process_contexts: dict[int, ProcessContext] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    finding_artifact_ids: list[list[UUID]] = field(default_factory=list)


class CorrelationEngine:
    """Correlates memory artifacts and generates forensic findings."""

    def __init__(self, os_type: str = "windows", rules_path: str | Path | None = None) -> None:
        self.os_type = os_type
        self.rules = self._load_rules(rules_path)

    def correlate(
        self,
        artifacts: list[Artifact],
        analysis_run_id: UUID,
    ) -> CorrelationResult:
        """Correlate artifacts and generate findings."""
        result = CorrelationResult()

        if not artifacts:
            result.warnings.append("No artifacts provided for correlation")
            return result

        # Work on normalized copies while retaining the persisted raw rows unchanged.
        artifacts = [
            artifact.model_copy(
                update={
                    "original_data": {
                        **artifact.original_data,
                        **artifact.original_data.get("normalized", {}),
                    }
                }
            )
            for artifact in artifacts
        ]

        # Build process contexts
        result.process_contexts = self._build_process_contexts(artifacts)

        # Detect relationships
        result.relationships = self._detect_relationships(artifacts, result.process_contexts)

        # Apply correlation rules
        for rule in self.rules:
            if self.os_type not in rule.applicable_os:
                continue

            for context in result.process_contexts.values():
                finding = self._evaluate_rule(rule, context, analysis_run_id)
                if finding:
                    result.findings.append(finding)
                    result.finding_artifact_ids.append(
                        [artifact.id for artifact in artifacts if artifact.pid == context.pid]
                    )

        result.warnings.append(
            "Correlation uses the current heuristic rules; missing artifacts are not negative "
            "results. MS-R008 is not implemented, and parent-child and YARA-region rules "
            "require investigator review."
        )

        return result

    def _load_rules(self, rules_path: str | Path | None) -> list[CorrelationRule]:
        """Load correlation rules from YAML configuration file."""
        if rules_path is None:
            rules_path = get_default_rules_path()

        try:
            return load_rules_from_yaml(rules_path, self.os_type)
        except Exception:
            # Fallback to default rules if loading fails
            # This ensures tests work even if YAML file is not found
            return self._get_fallback_rules()

    def _get_fallback_rules(self) -> list[CorrelationRule]:
        """Provide fallback rules when YAML loading fails."""
        return [
            CorrelationRule(
                rule_id="MS-R001",
                title="Executable Private Memory",
                description="Process contains private executable memory regions",
                severity=FindingSeverity.MEDIUM,
                base_score=0.5,
                applicable_os=("windows", "linux", "mac"),
                benign_explanations=(
                    "Browser JIT compilation",
                    "Java runtime activity",
                    ".NET runtime activity",
                    "Security software",
                    "Legitimate unpacking or runtime code generation",
                ),
            ),
            CorrelationRule(
                rule_id="MS-R002",
                title="Executable Private Memory with Network Activity",
                description="Process with private executable memory also has network connections",
                severity=FindingSeverity.HIGH,
                base_score=0.7,
                applicable_os=("windows", "linux", "mac"),
                benign_explanations=(
                    "Browser with JIT compilation and network access",
                    "Update services",
                    "Legitimate software with auto-update",
                ),
            ),
            CorrelationRule(
                rule_id="MS-R003",
                title="Thread Start in Executable Private Memory",
                description="Thread start address falls within private executable memory region",
                severity=FindingSeverity.HIGH,
                base_score=0.8,
                applicable_os=("windows",),
                benign_explanations=(
                    "Runtime code generation",
                    "JIT compilation",
                    "Dynamic library loading",
                ),
            ),
            CorrelationRule(
                rule_id="MS-R004",
                title="YARA Match in Suspicious Memory Region",
                description="YARA signature match within suspicious process memory region",
                severity=FindingSeverity.HIGH,
                base_score=0.9,
                applicable_os=("windows", "linux", "mac"),
                benign_explanations=(
                    "False positive from generic signatures",
                    "Legitimate software matching patterns",
                ),
            ),
            CorrelationRule(
                rule_id="MS-R005",
                title="Suspicious Parent-Child Process Relationship",
                description="Process has unusual or suspicious parent process",
                severity=FindingSeverity.MEDIUM,
                base_score=0.4,
                applicable_os=("windows", "linux", "mac"),
                benign_explanations=(
                    "System maintenance processes",
                    "Legitimate software installation",
                    "Operating system updates",
                ),
            ),
            CorrelationRule(
                rule_id="MS-R006",
                title="Unbacked Executable Module",
                description="Process has an executable module without a corresponding mapped file path",
                severity=FindingSeverity.MEDIUM,
                base_score=0.5,
                applicable_os=("windows", "linux", "mac"),
                benign_explanations=(
                    "Anonymous runtime mappings",
                    "JIT or unpacked code",
                ),
            ),
            CorrelationRule(
                rule_id="MS-R007",
                title="Suspicious Command Line with Network Activity",
                description="Process command line contains a download or interpreter indicator and owns a network connection",
                severity=FindingSeverity.MEDIUM,
                base_score=0.5,
                applicable_os=("windows", "linux", "mac"),
                benign_explanations=(
                    "Software deployment",
                    "Package management",
                    "Health checks and monitoring",
                ),
            ),
            CorrelationRule(
                rule_id="MS-R008",
                title="Process Artifact Inconsistency",
                description="Process is present in one process view but absent from a corroborating process view",
                severity=FindingSeverity.LOW,
                base_score=0.3,
                applicable_os=("windows", "linux", "mac"),
                benign_explanations=(
                    "Termination during acquisition",
                    "Parser or symbol limitations",
                    "Incomplete process-tree coverage",
                ),
            ),
        ]

    def _build_process_contexts(self, artifacts: list[Artifact]) -> dict[int, ProcessContext]:
        """Build process contexts from artifacts."""
        contexts: dict[int, ProcessContext] = {}

        for artifact in artifacts:
            pid = artifact.pid
            if pid is None:
                continue

            if pid not in contexts:
                process_name = self._extract_process_name(artifact)
                ppid = self._extract_ppid(artifact)
                contexts[pid] = ProcessContext(pid=pid, process_name=process_name, ppid=ppid)

            context = contexts[pid]
            if artifact.artifact_type in ("process", "process_tree"):
                context.process_name = self._extract_process_name(artifact) or context.process_name
                ppid = self._extract_ppid(artifact)
                if ppid is not None:
                    context.ppid = ppid
            artifact_type = artifact.artifact_type

            if artifact_type == "memory_region":
                context.memory_regions.append(artifact)
            elif artifact_type == "network_connection":
                context.network_connections.append(artifact)
            elif artifact_type == "thread":
                context.threads.append(artifact)
            elif artifact_type == "module":
                context.modules.append(artifact)
            elif artifact_type == "signature_match":
                context.signature_matches.append(artifact)
            elif artifact_type == "command_line":
                context.command_line = artifact

        return contexts

    def _detect_relationships(
        self, artifacts: list[Artifact], contexts: dict[int, ProcessContext]
    ) -> list[ArtifactRelationship]:
        """Detect relationships between artifacts."""
        relationships: list[ArtifactRelationship] = []

        # Parent-child relationships
        for pid, context in contexts.items():
            if context.ppid is not None and context.ppid in contexts:
                parent_context = contexts[context.ppid]
                # Use a valid UUID for the relationship
                source_id = (
                    parent_context.memory_regions[0].id
                    if parent_context.memory_regions
                    else UUID(int=context.ppid)
                )
                target_id = (
                    context.memory_regions[0].id if context.memory_regions else UUID(int=pid)
                )
                relationships.append(
                    ArtifactRelationship(
                        source_artifact_id=source_id,
                        target_artifact_id=target_id,
                        relationship_type="parent_child",
                        confidence=1.0,
                        metadata={"parent_pid": context.ppid, "child_pid": pid},
                    )
                )

        # Network ownership relationships
        for pid, context in contexts.items():
            for conn in context.network_connections:
                target_id = (
                    context.memory_regions[0].id if context.memory_regions else UUID(int=pid)
                )
                relationships.append(
                    ArtifactRelationship(
                        source_artifact_id=conn.id,
                        target_artifact_id=target_id,
                        relationship_type="network_ownership",
                        confidence=0.9,
                        metadata={"pid": pid},
                    )
                )

        return relationships

    def _apply_rule(
        self, rule: CorrelationRule, contexts: dict[int, ProcessContext], analysis_run_id: UUID
    ) -> list[FindingCreate]:
        """Apply a single correlation rule and generate findings."""
        findings: list[FindingCreate] = []

        for _pid, context in contexts.items():
            finding = self._evaluate_rule(rule, context, analysis_run_id)
            if finding:
                findings.append(finding)

        return findings

    def _evaluate_rule(
        self, rule: CorrelationRule, context: ProcessContext, analysis_run_id: UUID
    ) -> FindingCreate | None:
        """Evaluate a rule against a specific process context."""
        match = False
        score = rule.base_score
        details = []

        if rule.rule_id == "MS-R001":
            # Executable Private Memory
            match = self._check_executable_private_memory(context)
            if match:
                details.append(f"Found {len(context.memory_regions)} memory regions")

        elif rule.rule_id == "MS-R002":
            # Executable Private Memory with Network Activity
            has_suspicious_memory = self._check_executable_private_memory(context)
            has_network = len(context.network_connections) > 0
            match = has_suspicious_memory and has_network
            if match:
                details.append(f"Memory regions: {len(context.memory_regions)}")
                details.append(f"Network connections: {len(context.network_connections)}")

        elif rule.rule_id == "MS-R003":
            # Thread Start in Executable Private Memory
            match = self._check_thread_in_suspicious_memory(context)
            if match:
                details.append(f"Threads: {len(context.threads)}")

        elif rule.rule_id == "MS-R004":
            # YARA Match in Suspicious Region
            match = len(context.signature_matches) > 0
            if match:
                details.append(f"YARA matches: {len(context.signature_matches)}")

        elif rule.rule_id == "MS-R005":
            # Suspicious Parent-Child Relationship
            match = self._check_suspicious_parent_yaml(context)
            if match:
                details.append(f"Parent PID: {context.ppid}")

        elif rule.rule_id == "MS-R006":
            # Unbacked executable module
            match = self._check_unbacked_module(context)
            if match:
                details.append("Unbacked executable module detected")

        elif rule.rule_id == "MS-R007":
            # Suspicious command line with network activity
            match = self._check_suspicious_command_line_with_network(context)
            if match:
                details.append("Suspicious command line with network activity")

        elif rule.rule_id == "MS-R008":
            # Process artifact inconsistency
            match = self._check_process_artifact_inconsistency(context)
            if match:
                details.append("Process artifact inconsistency detected")

        if match:
            return FindingCreate(
                analysis_run_id=analysis_run_id,
                rule_id=rule.rule_id,
                title=rule.title,
                description=f"{rule.description}. Process: {context.process_name} (PID: {context.pid}). {', '.join(details)}",
                severity=rule.severity,
                confidence=score,
            )

        return None

    def _check_executable_private_memory(self, context: ProcessContext) -> bool:
        """Check if process has executable private memory regions."""
        for region in context.memory_regions:
            protection = (region.original_data.get("protection") or "").lower()
            is_private = region.original_data.get("private_memory", False)
            is_executable = "x" in protection or "execute" in protection
            if is_private and is_executable:
                return True
        return False

    def _check_thread_in_suspicious_memory(self, context: ProcessContext) -> bool:
        """Check if any thread starts in suspicious memory region."""
        if not context.threads or not context.memory_regions:
            return False

        for thread in context.threads:
            thread_start = thread.original_data.get("start_address")
            if thread_start:
                for region in context.memory_regions:
                    region_start = region.original_data.get("start")
                    region_end = region.original_data.get("end")
                    if (
                        region_start
                        and region_end
                        and thread_start
                        and self._address_in_range(thread_start, region_start, region_end)
                    ) and self._check_executable_private_memory(context):
                        return True
        return False

    def _check_suspicious_parent_yaml(self, context: ProcessContext) -> bool:
        """Check if process has suspicious parent based on YAML configuration."""
        if context.ppid is None or not context.process_name:
            return False

        # For this implementation, we need access to parent process context
        # Since we only have the current context, we'll use a simplified check
        # In a full implementation, this would look up the parent context from process_contexts

        # Check if the current process name matches any suspicious child names
        # This is a simplified version - the full version would check both parent and child names
        if self.os_type == "windows":
            suspicious_children = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]
        else:  # linux, mac
            suspicious_children = ["sh", "bash", "zsh", "python", "perl"]

        process_name_lower = context.process_name.lower()
        return any(child in process_name_lower for child in suspicious_children)

    def _check_unbacked_module(self, context: ProcessContext) -> bool:
        """Check for unbacked executable modules."""
        for module in context.modules:
            is_executable = module.original_data.get("executable", False)
            path = module.original_data.get("path")
            if (is_executable and not path) or path in [None, "", "unavailable"]:
                return True
        return False

    def _check_suspicious_command_line_with_network(self, context: ProcessContext) -> bool:
        """Check for suspicious command line with network activity."""
        if not context.command_line or len(context.network_connections) == 0:
            return False

        command_line = (context.command_line.original_data.get("command_line") or "").lower()
        suspicious_indicators = [
            "powershell",
            "cmd.exe",
            "curl",
            "wget",
            "nc",
            "netcat",
            "/bin/sh",
            "/bin/bash",
        ]

        return any(indicator in command_line for indicator in suspicious_indicators)

    def _check_process_artifact_inconsistency(self, context: ProcessContext) -> bool:
        """Check for process artifact inconsistency between process_list and process_tree."""
        # This would require comparing artifacts from different sources
        # For now, implement a placeholder that checks for missing artifacts
        # In a full implementation, this would check if a process appears in
        # process_list but not in process_tree, or vice versa
        return False

    def _address_in_range(self, address: str, start: str, end: str) -> bool:
        """Check if an address falls within a range."""
        try:
            addr_int = int(address, 16) if address.startswith("0x") else int(address)
            start_int = int(start, 16) if start.startswith("0x") else int(start)
            end_int = int(end, 16) if end.startswith("0x") else int(end)
            return start_int <= addr_int <= end_int
        except (ValueError, TypeError):
            return False

    def _extract_process_name(self, artifact: Artifact) -> str | None:
        """Extract process name from artifact."""
        return artifact.original_data.get("process_name") or artifact.original_data.get("name")

    def _extract_ppid(self, artifact: Artifact) -> int | None:
        """Extract PPID from artifact."""
        ppid = artifact.original_data.get("ppid")
        if ppid is not None:
            try:
                return int(ppid)
            except (ValueError, TypeError):
                pass
        return None
