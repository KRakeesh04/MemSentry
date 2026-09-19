"""Construct and execute one desktop analysis using the existing adapters."""

import json
import platform
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import volatility3.symbols
from volatility3.framework import constants

from memsentry.app.analysis_service import AnalysisService
from memsentry.app.case_service import workspace_database
from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.version import __version__
from memsentry.volatility.adapter import VolatilityAdapter
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugin_runner import PARSER_SPECS, PluginRunner
from memsentry.volatility.symbol_manager import SymbolManager
from memsentry.yara.scanner import YaraScanner


@dataclass(frozen=True)
class AnalysisRequest:
    workspace: str
    evidence_id: UUID
    os_type: str
    plugin_ids: tuple[str, ...]
    symbol_dir: Path
    yara_rules: tuple[Path, ...] = ()


def run_analysis(request: AnalysisRequest, started=lambda run: None):
    database = workspace_database(request.workspace)
    evidence = EvidenceRepository(database).get_by_id(request.evidence_id)
    if evidence is None or evidence.integrity_status != "verified":
        raise ValueError("Select registered evidence with verified integrity.")
    case = CaseRepository(database).get_by_id(evidence.case_id)
    if case is None or case.status != "open":
        raise ValueError("Analysis requires an open case.")
    if request.os_type not in ("windows", "linux"):
        raise ValueError("Desktop analysis currently supports Windows and Linux images.")
    if evidence.evidence_os and evidence.evidence_os != request.os_type:
        raise ValueError("Selected OS does not match the registered evidence OS.")
    registry = PluginRegistry()
    selected = registry.validate_selection(request.os_type, request.plugin_ids)
    if any(plugin.parser not in PARSER_SPECS or plugin.experimental for plugin in selected):
        raise ValueError("The selected plugin does not have a supported stable parser.")
    symbol_dir = request.symbol_dir.expanduser().resolve()
    if not symbol_dir.is_dir() or not (symbol_dir / request.os_type).is_dir():
        raise ValueError(f"Select a symbol root containing a {request.os_type}/ subfolder.")
    if not any(path.is_file() for path in (symbol_dir / request.os_type).rglob("*")):
        raise ValueError(
            f"No local {request.os_type} symbols found. Add matching symbols before analysis."
        )
    if request.yara_rules:
        try:
            import yara  # noqa: F401 -- validate the optional native dependency before starting.
        except ImportError as exc:
            raise ValueError(
                "YARA requires the optional yara-python dependency. Install it or disable YARA."
            ) from exc

        YaraScanner._resolve_rules(request.yara_rules)
    database.initialize()
    runs = AnalysisRunRepository(database)
    run = runs.create(
        AnalysisRunCreate(
            evidence_id=evidence.id,
            application_version=__version__,
            volatility_version=constants.PACKAGE_VERSION,
            host_os=HostOS({"Darwin": "macos"}.get(platform.system(), platform.system().lower())),
        )
    )
    started(run)
    previous_paths = list(volatility3.symbols.__path__)
    try:
        output = (
            Path(request.workspace).expanduser().resolve()
            / "cases"
            / str(case.id)
            / "analysis"
            / str(run.id)
        )
        output.mkdir(parents=True, exist_ok=False)
        (output / "selection.json").write_text(
            json.dumps(
                {
                    "evidence_id": str(evidence.id),
                    "baseline_sha256": evidence.sha256,
                    "os_type": request.os_type,
                    "plugins": list(request.plugin_ids),
                    "yara_requested": bool(request.yara_rules),
                    "yara_rules": [str(path) for path in request.yara_rules],
                    "symbol_root": str(symbol_dir),
                    "application_version": __version__,
                    "volatility_version": constants.PACKAGE_VERSION,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        # Volatility resolves ISF files through its symbol package search roots.
        volatility3.symbols.__path__ = [str(symbol_dir), *previous_paths]
        adapter = VolatilityAdapter(SymbolManager(str(symbol_dir)), output_dir=output / "files")
        plugins = PluginRunRepository(database)
        artifacts = ArtifactRepository(database)
        runner = PluginRunner(adapter, registry, plugins, artifacts, output / "raw")
        scanner = YaraScanner(plugins, artifacts, output / "raw")
        AnalysisService(
            adapter,
            registry,
            runner,
            scanner,
            os_type=request.os_type,
            dump_path=str(evidence.file_path),
        ).run(run.id, request.plugin_ids, request.yara_rules)
    except Exception as exc:
        runs.mark_failed(run.id, str(exc))
        raise
    finally:
        volatility3.symbols.__path__ = previous_paths
    return runs.get_by_id(run.id)
