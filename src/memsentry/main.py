"""Application entry point for MemSentry."""

from pathlib import Path

from memsentry.analysis.orchestrator import AnalysisOrchestrator
from memsentry.gui.application import create_application
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.volatility.runner import VolatilityRunner


def main() -> None:
    database = Database(Path("runtime/database/case.sqlite3"))
    database.initialize()

    case_repository = CaseRepository(database)
    evidence_repository = EvidenceRepository(database)
    analysis_run_repository = AnalysisRunRepository(database)
    plugin_run_repository = PluginRunRepository(database)

    volatility_runner = VolatilityRunner()
    analysis_orchestrator = AnalysisOrchestrator(
        analysis_run_repository=analysis_run_repository,
        plugin_run_repository=plugin_run_repository,
        evidence_repository=evidence_repository,
        volatility_runner=volatility_runner,
        timeout_seconds=900.0,
    )

    app = create_application(
        case_repository=case_repository,
        evidence_repository=evidence_repository,
        analysis_run_repository=analysis_run_repository,
        plugin_run_repository=plugin_run_repository,
        analysis_orchestrator=analysis_orchestrator,
    )
    app.exec()


if __name__ == "__main__":
    main()



