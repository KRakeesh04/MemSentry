"""Application-level orchestration of a Volatility analysis run."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from memsentry.app.workflow_service import WorkflowService
from memsentry.correlation.engine import CorrelationEngine
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository
from memsentry.volatility.adapter import VolatilityAdapter
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugin_runner import PluginRunner, PluginRunnerError
from memsentry.yara.scanner import YaraError, YaraScanner, YaraScanResult


class PartialAnalysisError(RuntimeError):
    def __init__(self, errors, results):
        super().__init__("\n".join(errors))
        self.results = results


class AnalysisService:
    """Coordinates selected Volatility plugins for a single evidence image.

    The service delegates execution and persistence to the ``PluginRunner``
    and verifies evidence integrity. Correlation is not invoked here yet.
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
        self.os_type = os_type
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
        normalized artifacts, and returns a per-plugin result dict.
        """
        database = self.plugin_runner.plugin_run_repository.database
        runs = AnalysisRunRepository(database)
        run = runs.get_by_id(analysis_run_id)
        if run is None:
            raise ValueError("Analysis run is not registered")
        evidence = EvidenceRepository(database).get_by_id(run.evidence_id)
        if evidence is None or Path(self.dump_path).resolve() != evidence.file_path.resolve():
            raise ValueError("Analysis path must match the registered evidence")
        runs.mark_running(analysis_run_id)
        try:
            result = WorkflowService(database).execute(
                analysis_run_id,
                "analyze",
                lambda: self._run_plugins(analysis_run_id, plugin_ids, yara_rule_paths),
            )
        except PartialAnalysisError as exc:
            runs.mark_completed_with_errors(analysis_run_id, str(exc))
            return exc.results
        except Exception as exc:
            runs.mark_failed(analysis_run_id, str(exc))
            raise
        runs.mark_completed(analysis_run_id)
        return result

    def _run_plugins(self, analysis_run_id, plugin_ids, yara_rule_paths):
        selected = self.plugin_registry.validate_selection(self.os_type, plugin_ids)
        database = self.plugin_runner.plugin_run_repository.database
        run = AnalysisRunRepository(database).get_by_id(analysis_run_id)
        events = WorkflowRepository(database)
        results: list[dict[str, Any]] = []
        errors = []
        for plugin in selected:
            events.record(
                run.evidence_id,
                analysis_run_id,
                "analyze",
                "operation",
                "running",
                message=f"Running {plugin.display_name if hasattr(plugin, 'display_name') else plugin.id}",
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
                evidence = EvidenceRepository(database).get_by_id(run.evidence_id)
                WorkflowService(database).verify(evidence, analysis_run_id, "analyze", "after")
            results.append(result)
            events.record(
                run.evidence_id,
                analysis_run_id,
                "analyze",
                "operation",
                "running",
                min(99, int(len(results) * 100 / max(len(selected) + bool(yara_rule_paths), 1))),
                message=f"Finished plugin {plugin.id}; final SHA-256 check still required",
            )

        if yara_rule_paths:
            events.record(
                run.evidence_id,
                analysis_run_id,
                "analyze",
                "operation",
                "running",
                message="Scanning memory with YARA",
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

        # TODO: Correlate the artifacts from all plugins and persist the results.

        return results
