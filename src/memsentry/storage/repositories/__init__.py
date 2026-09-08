"""Repository classes for persistent MemSentry data."""

from memsentry.storage.repositories.analysis_run_repository import (
    AnalysisRunNotFoundError,
    AnalysisRunRepository,
    AnalysisRunRepositoryError,
)
from memsentry.storage.repositories.artifact_repository import (
    ArtifactRepository,
    ArtifactRepositoryError,
)
from memsentry.storage.repositories.case_repository import (
    CaseNotFoundError,
    CaseRepository,
    CaseRepositoryError,
    DuplicateCaseNumberError,
)
from memsentry.storage.repositories.evidence_repository import (
    EvidenceNotFoundError,
    EvidenceRepository,
    EvidenceRepositoryError,
)
from memsentry.storage.repositories.finding_evidence_repository import (
    FindingEvidenceNotFoundError,
    FindingEvidenceRepository,
    FindingEvidenceRepositoryError,
)
from memsentry.storage.repositories.finding_repository import (
    FindingNotFoundError,
    FindingRepository,
    FindingRepositoryError,
)
from memsentry.storage.repositories.plugin_run_repository import (
    PluginRunNotFoundError,
    PluginRunRepository,
    PluginRunRepositoryError,
)

__all__ = [
    "AnalysisRunNotFoundError",
    "AnalysisRunRepository",
    "AnalysisRunRepositoryError",
    "ArtifactRepository",
    "ArtifactRepositoryError",
    "CaseNotFoundError",
    "CaseRepository",
    "CaseRepositoryError",
    "DuplicateCaseNumberError",
    "EvidenceNotFoundError",
    "EvidenceRepository",
    "EvidenceRepositoryError",
    "FindingEvidenceNotFoundError",
    "FindingEvidenceRepository",
    "FindingEvidenceRepositoryError",
    "FindingNotFoundError",
    "FindingRepository",
    "FindingRepositoryError",
    "PluginRunNotFoundError",
    "PluginRunRepository",
    "PluginRunRepositoryError",
]
