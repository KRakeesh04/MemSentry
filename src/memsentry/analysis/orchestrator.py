"""Analysis Orchestrator service managing execution of Volatility plugins for analysis runs."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from memsentry.models.analysis_run import AnalysisRun
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.utils.hashing import compute_file_sha256
from memsentry.volatility.runner import VolatilityResult, VolatilityRunner


class OrchestratorError(RuntimeError):
    """Base exception for analysis orchestration errors."""


class AnalysisRunNotFoundError(OrchestratorError):
    """Raised when the target AnalysisRun record is not found."""


class EvidenceRecordNotFoundError(OrchestratorError):
    """Raised when the target Evidence record is not found."""


class AnalysisOrchestrator:
    """
    Orchestrates execution of pending Volatility plugins for an AnalysisRun.

    Manages database state transitions (AnalysisRunRepository and PluginRunRepository),
    invokes VolatilityRunner, computes raw output SHA-256 digests, and persists output files.
    """

    def __init__(
        self,
        analysis_run_repository: AnalysisRunRepository,
        plugin_run_repository: PluginRunRepository,
        evidence_repository: EvidenceRepository,
        volatility_runner: VolatilityRunner,
        base_output_dir: Path | str = Path("runtime/analysis_outputs"),
        timeout_seconds: float | None = 300.0,
    ) -> None:
        self.analysis_run_repository = analysis_run_repository
        self.plugin_run_repository = plugin_run_repository
        self.evidence_repository = evidence_repository
        self.volatility_runner = volatility_runner
        self.base_output_dir = Path(base_output_dir)
        self.timeout_seconds = timeout_seconds

    def execute_analysis_run(
        self, analysis_run_id: UUID, timeout_seconds: float | None = None
    ) -> AnalysisRun:
        """
        Execute all pending plugin runs for an existing AnalysisRun.

        Args:
            analysis_run_id: The UUID of the staged AnalysisRun to execute.
            timeout_seconds: Optional timeout override in seconds per plugin.

        Returns:
            The updated AnalysisRun model reflecting final execution state.
        """
        analysis_run = self.analysis_run_repository.get_by_id(analysis_run_id)
        if analysis_run is None:
            raise AnalysisRunNotFoundError(f"AnalysisRun not found: {analysis_run_id}")

        evidence = self.evidence_repository.get_by_id(analysis_run.evidence_id)
        if evidence is None:
            err_msg = f"Evidence record not found for ID: {analysis_run.evidence_id}"
            self.analysis_run_repository.mark_failed(analysis_run_id, err_msg)
            raise EvidenceRecordNotFoundError(err_msg)

        if not evidence.file_path.exists() or not evidence.file_path.is_file():
            err_msg = f"Evidence RAM dump file missing: {evidence.file_path}"
            return self.analysis_run_repository.mark_failed(analysis_run_id, err_msg)

        # Mark analysis run as running
        analysis_run = self.analysis_run_repository.mark_running(analysis_run_id)

        # Retrieve pending plugin runs
        plugin_runs = self.plugin_run_repository.list_by_analysis_run(analysis_run_id)

        if not plugin_runs:
            err_msg = "No plugin runs configured for this analysis run."
            return self.analysis_run_repository.mark_completed_with_errors(
                analysis_run_id, error_message=err_msg
            )

        run_output_dir = self.base_output_dir / str(analysis_run_id)
        run_output_dir.mkdir(parents=True, exist_ok=True)

        successful_count = 0
        failed_count = 0

        try:
            for prun in plugin_runs:
                # Mark individual plugin run as running
                self.plugin_run_repository.mark_running(prun.id)

                effective_timeout = (
                    timeout_seconds
                    if timeout_seconds is not None
                    else self.timeout_seconds
                )
                try:
                    result: VolatilityResult = self.volatility_runner.run_plugin(
                        evidence_path=evidence.file_path,
                        plugin_name=prun.plugin_name,
                        output_dir=run_output_dir,
                        evidence_os=evidence.evidence_os,
                        timeout_seconds=effective_timeout,
                    )
                except Exception as exc:
                    self.plugin_run_repository.mark_failed(
                        prun.id, error_message=f"Plugin execution exception: {exc}"
                    )
                    failed_count += 1
                    continue

                if (
                    result.success
                    and result.output_path is not None
                    and result.output_path.exists()
                ):
                    output_sha256 = compute_file_sha256(result.output_path)
                    self.plugin_run_repository.mark_completed(
                        prun.id,
                        raw_output_path=result.output_path,
                        raw_output_sha256=output_sha256,
                    )
                    successful_count += 1
                else:
                    err_detail = (
                        result.error_message
                        or result.stderr
                        or "Unknown plugin execution error"
                    )
                    out_path = (
                        result.output_path
                        if (result.output_path and result.output_path.exists())
                        else None
                    )
                    out_sha = compute_file_sha256(out_path) if out_path else None

                    self.plugin_run_repository.mark_failed(
                        prun.id,
                        error_message=err_detail,
                        raw_output_path=out_path,
                        raw_output_sha256=out_sha,
                    )
                    failed_count += 1

        except Exception as exc:
            err_msg = f"Fatal orchestration error: {exc}"
            return self.analysis_run_repository.mark_failed(analysis_run_id, err_msg)

        # Final AnalysisRun state transition
        if failed_count == 0 and successful_count > 0:
            return self.analysis_run_repository.mark_completed(analysis_run_id)

        if successful_count > 0:
            return self.analysis_run_repository.mark_completed_with_errors(
                analysis_run_id,
                error_message=f"{failed_count} of {len(plugin_runs)} plugin(s) failed.",
            )

        return self.analysis_run_repository.mark_failed(
            analysis_run_id,
            error_message=f"All {len(plugin_runs)} plugin(s) failed.",
        )
