"""Orchestrate one or more Volatility plugin runs and persist their results."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from memsentry.models.artifact import ArtifactCreate
from memsentry.models.plugin_run import PluginRunCreate
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.volatility.adapter import VolatilityAdapter
from memsentry.volatility.os_utils import normalise_os
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugins.cmdline_parser import CmdlineParser
from memsentry.volatility.plugins.dlllist_parser import DlllistParser
from memsentry.volatility.plugins.evidence_parsers import PsScanParser, ThreadsParser, VadInfoParser
from memsentry.volatility.plugins.handles_parser import HandlesParser
from memsentry.volatility.plugins.info_parser import InfoParser
from memsentry.volatility.plugins.malfind_parser import MalfindParser
from memsentry.volatility.plugins.netscan_parser import NetscanParser
from memsentry.volatility.plugins.pslist_parser import PsListParser
from memsentry.volatility.plugins.pstree_parser import PstreeParser


class PluginRunnerError(RuntimeError):
    """Raised when a plugin run cannot be completed successfully."""


def _normalized_fields(artifact: Any) -> dict[str, Any]:
    """Return a parser artifact's typed fields, excluding raw/provenance.

    Kept inside ``original_data`` so the normalized record is persisted in the
    existing ``artifacts`` table without changing the schema or repositories.
    """
    fields = dict(dataclasses.asdict(artifact)) if dataclasses.is_dataclass(artifact) and not isinstance(artifact, type) else {}
    fields.pop("original_data", None)
    fields.pop("provenance", None)
    return fields


@dataclass(frozen=True, slots=True)
class ParserSpec:
    """How to turn one parser's result into persisted artifacts."""

    parser: Any
    artifact_type: str
    artifacts_attr: str
    pid_attr: str | None = "pid"


# Map the registry's parser name to a parser instance and its artifact shape.
PARSER_SPECS: dict[str, ParserSpec] = {
    "psscan_parser": ParserSpec(PsScanParser(), "process", "processes"),
    "threads_parser": ParserSpec(ThreadsParser(), "thread", "threads"),
    "vadinfo_parser": ParserSpec(VadInfoParser(), "memory_region", "regions"),
    "pslist_parser": ParserSpec(PsListParser(), "process", "processes"),
    "pstree_parser": ParserSpec(PstreeParser(), "process_tree", "processes"),
    "cmdline_parser": ParserSpec(CmdlineParser(), "command_line", "command_lines"),
    "malfind_parser": ParserSpec(MalfindParser(), "memory_region", "regions"),
    "handles_parser": ParserSpec(HandlesParser(), "handle", "handles"),
    "netscan_parser": ParserSpec(NetscanParser(), "network_connection", "connections"),
    "dlllist_parser": ParserSpec(DlllistParser(), "module", "modules"),
    "info_parser": ParserSpec(InfoParser(), "system_info", "systems", pid_attr=None),
}


class PluginRunner:
    """Orchestrates the execution of Volatility plugins and the processing of their results.

    The runner follows the dependency-injection flow: PluginRegistry resolves
    the approved Volatility plugin, the VolatilityAdapter executes it read-only,
    the result is parsed, and the raw output plus normalized artifacts are
    persisted through the provided repositories.
    """

    def __init__(
        self,
        adapter: VolatilityAdapter,
        plugin_registry: PluginRegistry,
        plugin_run_repository: PluginRunRepository,
        artifact_repository: ArtifactRepository,
        raw_output_dir: str | Path | None = None,
    ) -> None:
        self.adapter = adapter
        self.plugin_registry = plugin_registry
        self.plugin_run_repository = plugin_run_repository
        self.artifact_repository = artifact_repository
        self.raw_output_dir = Path(raw_output_dir) if raw_output_dir else None

    def run_plugin(
        self, evidence_path: str, analysis_run_id: UUID, plugin_id: str, os_type: str
    ) -> dict[str, Any]:
        """Run a Volatility plugin and process its results.

        Returns a dict with ``plugin_run`` (the finished database record),
        ``parsed_result`` (the parser's result), ``raw_output_path`` (the saved
        raw output file), and ``artifacts`` (the persisted normalized rows).
        Raises :class:`PluginRunnerError` when the plugin cannot be completed.
        """
        normalised_os = normalise_os(os_type)
        definition = self.plugin_registry.get_plugin(plugin_id)
        # Validate the selection and resolve the Volatility plugin name.
        self.plugin_registry.get_volatility_plugin(plugin_id, normalised_os)
        plugin_name = definition.volatility_plugin_for(normalised_os)
        if plugin_name is None:
            raise PluginRunnerError(f"Plugin {plugin_id!r} is unavailable for {normalised_os}")
        parser_spec = self._parser_spec(definition.parser)

        run = self.plugin_run_repository.create(
            PluginRunCreate(
                analysis_run_id=analysis_run_id,
                plugin_name=plugin_name,
                configuration={"plugin_id": plugin_id, "os_type": normalised_os},
            )
        )
        self.plugin_run_repository.mark_running(run.id)

        try:
            self.adapter.initialize(normalised_os)
            execution = self.adapter.run_plugin(plugin_name, evidence_path)
            raw_output_path = self._store_raw_output(run.id, execution.plugin_name, execution.raw_output)
            raw_hash = self._sha256_file(raw_output_path)

            parsed = parser_spec.parser.parse(execution.raw_output, normalised_os)
            artifacts = self._persist_artifacts(
                parser_spec, parsed, analysis_run_id, run.id
            )

            completed_run = self.plugin_run_repository.mark_completed(
                run.id, raw_output_path, raw_hash
            )
            return {
                "plugin_run": completed_run,
                "parsed_result": parsed,
                "raw_output_path": str(raw_output_path),
                "artifacts": artifacts,
            }
        except Exception as error:
            self._mark_failed(run.id, error)
            raise PluginRunnerError(
                f"Plugin run '{plugin_id}' on '{evidence_path}' failed: {error}"
            ) from error

    def _parser_spec(self, parser_name: str) -> ParserSpec:
        try:
            return PARSER_SPECS[parser_name]
        except KeyError as error:
            raise PluginRunnerError(f"No parser available for: {parser_name}") from error

    def _store_raw_output(
        self, run_id: UUID, plugin_name: str, raw_output: str
    ) -> Path:
        output_root = self.raw_output_dir or (Path.cwd() / "raw_output")
        output_root.mkdir(parents=True, exist_ok=True)
        filename = f"{run_id}_{plugin_name.replace('.', '_')}.json"
        output_path = output_root / filename
        output_path.write_text(raw_output, encoding="utf-8")
        return output_path

    def _persist_artifacts(
        self,
        spec: ParserSpec,
        parsed_result: Any,
        analysis_run_id: UUID,
        plugin_run_id: UUID,
    ) -> list[Any]:
        artifacts = getattr(parsed_result, spec.artifacts_attr, ())
        create_items = []
        for artifact in artifacts:
            pid = getattr(artifact, spec.pid_attr, None) if spec.pid_attr else None
            if pid is not None and pid < 0:
                pid = None
            original = dict(artifact.original_data)
            original["normalized"] = _normalized_fields(artifact)
            create_items.append(
                ArtifactCreate(
                    analysis_run_id=analysis_run_id,
                    plugin_run_id=plugin_run_id,
                    artifact_type=spec.artifact_type,
                    pid=pid,
                    original_data=original,
                    provenance=artifact.provenance,
                )
            )
        if not create_items:
            return []
        return self.artifact_repository.create_many(create_items)

    def _mark_failed(self, run_id: UUID, error: Exception) -> None:
        with contextlib.suppress(Exception):
            self.plugin_run_repository.mark_failed(run_id, str(error))

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
