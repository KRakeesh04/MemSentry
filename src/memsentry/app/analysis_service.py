"""Application-level orchestration of a Volatility analysis run."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import UUID

from memsentry.app.workflow_service import WorkflowService
from memsentry.correlation.engine import CorrelationEngine, CorrelationResult
from memsentry.models.artifact import Artifact
from memsentry.models.finding import Finding
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository
from memsentry.volatility.adapter import VolatilityAdapter
from memsentry.volatility.os_utils import normalise_os
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugin_runner import PluginRunner, PluginRunnerError
from memsentry.yara.scanner import YaraError, YaraScanner, YaraScanResult


class PartialAnalysisError(RuntimeError):
    def __init__(self, errors: Sequence[str], results: list[dict[str, Any]]) -> None:
        super().__init__("\n".join(errors))
        self.results = results


class AnalysisService:
    """Coordinates selected Volatility plugins for a single evidence image.

    The service delegates execution and persistence to the ``PluginRunner``
    verifies evidence integrity, correlates persisted artifacts, and stores
    findings with their source evidence. Reports are handled separately.
    """

    def __init__(
        self,
        volatility_adapter: VolatilityAdapter,
        plugin_registry: PluginRegistry,
        plugin_runner: PluginRunner,
        yara_scanner: YaraScanner,
        correlation_engine: CorrelationEngine | None = None,
        os_type: str = "windows",
        dump_path: str = "",
    ) -> None:
        self.volatility_adapter = volatility_adapter
        self.plugin_registry = plugin_registry
        self.plugin_runner = plugin_runner
        self.yara_scanner = yara_scanner
        self.correlation_engine = correlation_engine
        self.os_type = normalise_os(os_type)
        self.dump_path = dump_path

    def run(
        self,
        analysis_run_id: Any,
        plugin_ids: Sequence[str],
        yara_rule_paths: Sequence[str | Path] = (),
    ) -> list[dict[str, Any]]:
        """Analyze the evidence using the specified Volatility plugins.

        For each ``plugin_id`` the underlying :class:`PluginRunner` executes the
        plugin against the read-only image, persists the raw output and
        normalized artifacts, and returns a per-plugin result dict. The final
        entry contains the correlation result and persisted findings. Each
        major stage verifies the evidence before and after execution.
        """
        database = self.plugin_runner.plugin_run_repository.database
        runs = AnalysisRunRepository(database)
        run = runs.get_by_id(analysis_run_id)
        if run is None:
            raise ValueError("Analysis run is not registered")
        evidence = EvidenceRepository(database).get_by_id(run.evidence_id)
        if evidence is None or Path(self.dump_path).resolve() != evidence.file_path.resolve():
            raise ValueError("Analysis path must match the registered evidence")
        if run.status != "pending":
            raise ValueError("Analysis run has already started; create a new run")
        if evidence.evidence_os and normalise_os(evidence.evidence_os) != self.os_type:
            raise ValueError("Selected OS does not match the registered evidence OS")
        if self.correlation_engine is not None and self.correlation_engine.os_type != self.os_type:
            raise ValueError("Correlation engine OS does not match the analysis OS")
        runs.mark_running(analysis_run_id)
        workflow = WorkflowService(database)
        errors: list[str] = []
        try:
            try:
                result = workflow.execute(
                    analysis_run_id,
                    "analyze",
                    lambda: self._run_plugins(analysis_run_id, plugin_ids, yara_rule_paths),
                )
            except PartialAnalysisError as exc:
                errors.append(str(exc))
                result = exc.results
            artifacts = ArtifactRepository(database).list_by_analysis_run(run.id)
            engine = self.correlation_engine or CorrelationEngine(self.os_type)
            def correlate() -> CorrelationResult:
                correlation = engine.correlate(artifacts, run.id)
                if errors:
                    correlation.warnings.append("Analysis is incomplete: " + "\n".join(errors))
                for warning in correlation.warnings:
                    workflow.events.record(
                        evidence.id, run.id, "correlate", "operation", "running", message=warning
                    )
                return correlation

            correlation = workflow.execute(run.id, "correlate", correlate)
            findings = workflow.execute(
                run.id, "findings", lambda: self._store_findings(run.id, correlation, artifacts)
            )
            result.append({"correlation": correlation, "findings": findings})
        except Exception as exc:
            runs.mark_failed(analysis_run_id, str(exc))
            raise
        if errors:
            runs.mark_completed_with_errors(analysis_run_id, "\n".join(errors))
        else:
            runs.mark_completed(analysis_run_id)
        return result

    def _store_findings(
        self, run_id: UUID, correlation: CorrelationResult, artifacts: list[Artifact]
    ) -> list[Finding]:
        if len(correlation.findings) != len(correlation.finding_artifact_ids):
            raise ValueError("Correlation findings are missing artifact provenance")
        by_id = {artifact.id: artifact for artifact in artifacts}
        items = []
        for finding, artifact_ids in zip(
            correlation.findings, correlation.finding_artifact_ids, strict=True
        ):
            if finding.analysis_run_id != run_id:
                raise ValueError("Correlation finding belongs to another analysis run")
            if any(artifact_id not in by_id for artifact_id in artifact_ids):
                raise ValueError("Correlation finding references an unknown artifact")
            items.append(
                (finding, [by_id[artifact_id] for artifact_id in dict.fromkeys(artifact_ids)])
            )
        database = self.plugin_runner.plugin_run_repository.database
        return FindingRepository(database).create_many_with_evidence(items)

    def _run_plugins(
        self,
        analysis_run_id: UUID,
        plugin_ids: Sequence[str],
        yara_rule_paths: Sequence[str | Path],
    ) -> list[dict[str, Any]]:
        selected = self.plugin_registry.validate_selection(self.os_type, plugin_ids)
        database = self.plugin_runner.plugin_run_repository.database
        run = AnalysisRunRepository(database).get_by_id(analysis_run_id)
        if run is None:
            raise ValueError("Analysis run is not registered")
        events = WorkflowRepository(database)
        if selected:
            events.record(
                run.evidence_id,
                analysis_run_id,
                "analyze",
                "operation",
                "running",
                message="Preparing Volatility symbol directory and search path",
            )
            self.volatility_adapter.load_symbols(self.os_type)
        results: list[dict[str, Any]] = []
        errors = []
        total_steps = len(selected) + bool(yara_rule_paths)
        for index, plugin in enumerate(selected, start=1):
            events.record(
                run.evidence_id,
                analysis_run_id,
                "analyze",
                "operation",
                "running",
                message=(
                    f"Running plugin {index}/{total_steps}: "
                    f"{plugin.display_name if hasattr(plugin, 'display_name') else plugin.id}"
                ),
            )
            try:
                result = self.plugin_runner.run_plugin(
                    evidence_path=self.dump_path,
                    analysis_run_id=analysis_run_id,
                    plugin_id=plugin.id,
                    os_type=self.os_type,
                )
            except PluginRunnerError as exc:
                errors.append(str(exc))
                result = {"plugin_id": plugin.id, "error": str(exc)}
                # The enclosing analyze workflow verifies the image after all selected
                # plugins finish. Rehashing a large image after every plugin failure
                # made all-plugin runs appear stalled and duplicated that integrity gate.
            results.append(result)
            events.record(
                run.evidence_id,
                analysis_run_id,
                "analyze",
                "operation",
                "running",
                min(99, int(len(results) * 100 / max(total_steps, 1))),
                message=f"Finished plugin {plugin.id}; final SHA-256 check still required",
            )

        if yara_rule_paths:
            events.record(
                run.evidence_id,
                analysis_run_id,
                "analyze",
                "operation",
                "running",
                message=f"Running YARA scan {len(selected) + 1}/{total_steps}",
            )
            try:
                yara_result = self.yara_scanner.scan(
                    self.dump_path, analysis_run_id, tuple(yara_rule_paths), self.os_type
                )
            except YaraError as exc:
                errors.append(str(exc))
                results.append({"yara_error": str(exc), "requested": True})
                raise PartialAnalysisError(errors, results) from exc
        else:
            yara_result = YaraScanResult(False, None, None, {}, ())
        results.append({"yara": yara_result})
        if errors:
            raise PartialAnalysisError(errors, results)

        return results
