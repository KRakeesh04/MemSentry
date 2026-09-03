"""Persistence operations for normalized Volatility artifacts."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from uuid import UUID, uuid4

from memsentry.models.artifact import Artifact, ArtifactCreate
from memsentry.storage.database import Database


class ArtifactRepositoryError(RuntimeError):
    """Raised when an artifact database operation fails."""


class ArtifactRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, data: ArtifactCreate) -> Artifact:
        artifact_id, created_at = uuid4(), datetime.now(UTC)
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """INSERT INTO artifacts
                    (id, analysis_run_id, plugin_run_id, artifact_type, pid,
                     original_data_json, provenance_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(artifact_id),
                        str(data.analysis_run_id),
                        str(data.plugin_run_id),
                        data.artifact_type,
                        data.pid,
                        json.dumps(data.original_data),
                        json.dumps(data.provenance),
                        created_at.isoformat(),
                    ),
                )
        except sqlite3.Error as exc:
            raise ArtifactRepositoryError("Could not create artifact.") from exc
        result = self.get_by_id(artifact_id)
        if result is None:
            raise ArtifactRepositoryError("Artifact was inserted but could not be retrieved.")
        return result

    def create_many(self, data: list[ArtifactCreate]) -> list[Artifact]:
        if not data:
            return []

        artifact_ids: list[UUID] = []
        try:
            with self.database.transaction() as connection:
                for item in data:
                    artifact_id, created_at = uuid4(), datetime.now(UTC)
                    artifact_ids.append(artifact_id)
                    connection.execute(
                        """INSERT INTO artifacts
                        (id, analysis_run_id, plugin_run_id, artifact_type, pid,
                        original_data_json, provenance_json, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            str(artifact_id),
                            str(item.analysis_run_id),
                            str(item.plugin_run_id),
                            item.artifact_type,
                            item.pid,
                            json.dumps(item.original_data),
                            json.dumps(item.provenance),
                            created_at.isoformat(),
                        ),
                    )
        except sqlite3.Error as exc:
            raise ArtifactRepositoryError("Could not create artifacts.") from exc
        artifacts: list[Artifact] = []
        for artifact_id in artifact_ids:
            artifact = self.get_by_id(artifact_id)
            if artifact is None:
                raise ArtifactRepositoryError(
                    "Artifacts were inserted but could not be retrieved."
                )
            artifacts.append(artifact)
        return artifacts

    def get_by_id(self, artifact_id: UUID) -> Artifact | None:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE id = ?", (str(artifact_id),)
            ).fetchone()
        return self._row_to_artifact(row) if row is not None else None

    def list_by_analysis_run(self, analysis_run_id: UUID) -> list[Artifact]:
        return self._list("analysis_run_id", analysis_run_id)

    def list_by_plugin_run(self, plugin_run_id: UUID) -> list[Artifact]:
        return self._list("plugin_run_id", plugin_run_id)

    def list_by_type(self, analysis_run_id: UUID, artifact_type: str) -> list[Artifact]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM artifacts WHERE analysis_run_id = ? AND artifact_type = ? ORDER BY created_at, id",
                (str(analysis_run_id), artifact_type),
            ).fetchall()
        return [self._row_to_artifact(row) for row in rows]

    def _list(self, column: str, value: UUID) -> list[Artifact]:
        with self.database.connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM artifacts WHERE {column} = ? ORDER BY created_at, id", (str(value),)
            ).fetchall()
        return [self._row_to_artifact(row) for row in rows]

    @staticmethod
    def _row_to_artifact(row: sqlite3.Row) -> Artifact:
        return Artifact(
            id=UUID(row["id"]),
            analysis_run_id=UUID(row["analysis_run_id"]),
            plugin_run_id=UUID(row["plugin_run_id"]),
            artifact_type=row["artifact_type"],
            pid=row["pid"],
            original_data=json.loads(row["original_data_json"]),
            provenance=json.loads(row["provenance_json"]),
            created_at=row["created_at"],
        )
