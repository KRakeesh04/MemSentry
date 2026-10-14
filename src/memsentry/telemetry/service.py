"""Read-only, SHA-256-verified optional imports through existing repositories."""

from __future__ import annotations

import hashlib
import importlib
import json
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID
from xml.etree import ElementTree

from memsentry.models.artifact import Artifact
from memsentry.models.plugin_run import PluginRunCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.telemetry.adapters import TelemetryError, parse_edr_record, parse_windows_xml


class TelemetryImportService:
    def __init__(self, database: Database) -> None:
        self.runs = PluginRunRepository(database)
        self.artifacts = ArtifactRepository(database)

    @staticmethod
    def _hash(path: Path) -> str:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def import_file(
        self, path: Path, analysis_run_id: UUID, *, acquisition_id: str, format: str
    ) -> list[Artifact]:
        """Formats: xml (Event/Events), evtx (optional python-evtx), edr_jsonl.

        acquisition_id is caller-supplied evidence scope, not inferred from file proximity.
        No artifacts are committed if any record or the final integrity check fails.
        Plugin-run metadata provides the audit record and original source hash.
        """
        if format not in {"xml", "evtx", "edr_jsonl"} or not acquisition_id:
            raise TelemetryError("Provide a supported format and explicit acquisition scope")
        path = path.expanduser().resolve()
        before = self._hash(path)
        run = self.runs.create(
            PluginRunCreate(
                analysis_run_id=analysis_run_id,
                plugin_name=f"telemetry.import.{format}",
                configuration={
                    "source_file": str(path),
                    "source_sha256": before,
                    "acquisition_id": acquisition_id,
                    "adapter_version": 1,
                },
            )
        )
        self.runs.mark_running(run.id)
        try:
            records = []
            if format == "edr_jsonl":
                with path.open(encoding="utf-8") as stream:
                    for line_number, line in enumerate(stream, 1):
                        if line.strip():
                            try:
                                record = json.loads(line)
                                if not isinstance(record, dict):
                                    raise TelemetryError("Record must be an object")
                                records.append(
                                    parse_edr_record(
                                        record,
                                        analysis_run_id,
                                        run.id,
                                        acquisition_id=acquisition_id,
                                        source_file=str(path),
                                    )
                                )
                            except (ValueError, TypeError) as exc:
                                raise TelemetryError(f"EDR line {line_number}: {exc}") from exc
            else:
                for xml in self._xml_records(path, format):
                    records.append(
                        parse_windows_xml(
                            xml,
                            analysis_run_id,
                            run.id,
                            acquisition_id=acquisition_id,
                            source_file=str(path),
                        )
                    )
            if self._hash(path) != before:
                raise TelemetryError(
                    "Telemetry source SHA-256 changed during import; no artifacts stored"
                )
            result = self.artifacts.create_many(records)
            self.runs.mark_completed(run.id, path, before)
            return result
        except Exception as exc:
            self.runs.mark_failed(run.id, str(exc), path, before)
            raise

    @staticmethod
    def _xml_records(path: Path, format: str) -> Iterator[str]:
        if format == "evtx":
            try:
                evtx = importlib.import_module("Evtx.Evtx")
            except ImportError as exc:
                raise TelemetryError(
                    "Binary EVTX requires optional python-evtx; exported Windows XML is supported without it"
                ) from exc
            with evtx.Evtx(str(path)) as log:
                for record in log.records():
                    yield record.xml()
        else:
            # Reject entity declarations before parsing; stream events without retaining the tree.
            with path.open("rb") as stream:
                tail = b""
                for chunk in iter(lambda: stream.read(65536), b""):
                    sample = (tail + chunk).upper()
                    if b"<!DOCTYPE" in sample or b"<!ENTITY" in sample:
                        raise TelemetryError("XML entity declarations are unsupported")
                    tail = chunk[-16:]
            for _, element in ElementTree.iterparse(path, events=("end",)):
                if element.tag.rsplit("}", 1)[-1] == "Event":
                    yield ElementTree.tostring(element, encoding="unicode")
                    element.clear()
