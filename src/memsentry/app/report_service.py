from datetime import UTC, datetime
from uuid import UUID

from memsentry.models.report import ReportData, ReportOptions
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository


class ReportService:
    def __init__(
        self,
        case_repo: CaseRepository,
        evidence_repo: EvidenceRepository,
        analysis_run_repo: AnalysisRunRepository,
        plugin_run_repo: PluginRunRepository,
        finding_repo: FindingRepository,
        artifact_repo: ArtifactRepository,
        workflow_repo: WorkflowRepository,
    ) -> None:
        self.case_repo = case_repo
        self.evidence_repo = evidence_repo
        self.analysis_run_repo = analysis_run_repo
        self.plugin_run_repo = plugin_run_repo
        self.finding_repo = finding_repo
        self.artifact_repo = artifact_repo
        self.workflow_repo = workflow_repo

    def aggregate_report_data(self, case_id: UUID | str, options: ReportOptions) -> ReportData:
        """Collect all case data to build the report."""
        case_uuid = UUID(str(case_id))
        case = self.case_repo.get_by_id(case_uuid)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        evidences = self.evidence_repo.list_by_case(case_uuid)
        findings = []
        for evidence in evidences:
            runs = self.analysis_run_repo.list_by_evidence(evidence.id)
            for run in runs:
                findings.extend(self.finding_repo.list_by_analysis_run(run.id))

        plugin_runs = None
        artifacts = None
        workflow_events = None

        if (
            options.include_plugin_runs
            or options.include_artifacts
            or options.include_workflow_history
        ):
            # Gather runs for evidences
            all_plugin_runs = []
            all_artifacts = []
            all_events = []

            for evidence in evidences:
                runs = self.analysis_run_repo.list_by_evidence(evidence.id)
                for run in runs:
                    if options.include_plugin_runs or options.include_artifacts:
                        pr = self.plugin_run_repo.list_by_analysis_run(run.id)
                        if options.include_plugin_runs:
                            all_plugin_runs.extend(pr)

                        if options.include_artifacts:
                            for p in pr:
                                arts = self.artifact_repo.list_by_plugin_run(p.id)
                                all_artifacts.extend(arts)

                if options.include_workflow_history:
                    events = self.workflow_repo.list_events(evidence_id=evidence.id)
                    all_events.extend(events)

            if options.include_plugin_runs:
                plugin_runs = all_plugin_runs
            if options.include_artifacts:
                artifacts = all_artifacts
            if options.include_workflow_history:
                workflow_events = all_events

        return ReportData(
            generated_at=datetime.now(UTC),
            case=case,
            evidences=evidences,
            findings=findings,
            plugin_runs=plugin_runs,
            artifacts=artifacts,
            workflow_events=workflow_events,
        )
