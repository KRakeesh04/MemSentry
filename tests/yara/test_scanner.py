from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.yara.scanner import YaraScanner


def _analysis_run(db: Database, tmp_path: Path) -> UUID:
    case = CaseRepository(db).create(CaseCreate(case_number="YARA-1", name="YARA test"))
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename="sample.raw",
            file_path=tmp_path / "sample.raw",
            file_size_bytes=1,
            sha256="a" * 64,
        )
    )
    return AnalysisRunRepository(db).create(
        AnalysisRunCreate(
            evidence_id=evidence.id,
            application_version="0.1.0",
            volatility_version="2.0.0",
            host_os=HostOS.LINUX,
        )
    ).id


def test_yara_scan_persists_match_and_preserves_evidence(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    database.initialize()
    evidence = tmp_path / "sample.raw"
    evidence.write_bytes(b"safe-prefix suspicious")
    rules = tmp_path / "indicator.yara"
    rules.write_text("rule test_rule { strings: $x = \"suspicious\" condition: $x }", encoding="utf-8")

    fake_yara = SimpleNamespace(
        compile=lambda **_: SimpleNamespace(
            match=lambda _: [
                SimpleNamespace(
                    rule="test_rule",
                    namespace="indicator.yara",
                    tags=["test"],
                    meta={"description": "test"},
                    strings=[(12, "$x", b"suspicious")],
                )
            ]
        )
    )
    run_id = _analysis_run(database, tmp_path)
    scanner = YaraScanner(
        PluginRunRepository(database),
        ArtifactRepository(database),
        tmp_path / "raw",
        yara_module=fake_yara,
    )

    result = scanner.scan(evidence, run_id, [rules], "linux")

    assert result.requested is True
    assert result.matches[0].strings[0]["offset"] == 12
    assert evidence.read_bytes() == b"safe-prefix suspicious"
    artifacts = ArtifactRepository(database).list_by_type(run_id, "signature_match")
    assert artifacts[0].original_data["normalized"]["rule"] == "test_rule"
    assert artifacts[0].provenance["source"] == "yara"


def test_empty_rules_are_reported_as_not_requested(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    database.initialize()
    scanner = YaraScanner(PluginRunRepository(database), ArtifactRepository(database))

    result = scanner.scan(tmp_path / "missing.raw", uuid4(), [])

    assert result.requested is False
    assert result.matches == ()
