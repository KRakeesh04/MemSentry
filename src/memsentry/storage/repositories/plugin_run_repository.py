from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from memsentry.models.plugin_run import (
    PluginRun,
    PluginRunCreate,
    PluginRunStatus,
)
from memsentry.storage.database import Database


class PluginRunRepositoryError(RuntimeError):
    """Raised when a plugin run database operation fails."""


class PluginRunNotFoundError(PluginRunRepositoryError):
    """Raised when a requested plugin run record is not found."""


class PluginRunRepository:
    """Store and retrieve plugin run records."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, data: PluginRunCreate) -> PluginRun:
        """Create and return a new plugin run in pending state."""

        plugin_run_id = uuid4()
        config_json = json.dumps(data.configuration)

        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO plugin_runs (
                        id,
                        analysis_run_id,
                        plugin_name,
                        status,
                        configuration_json,
                        raw_output_path,
                        raw_output_sha256,
                        started_at,
                        completed_at,
                        error_message
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(plugin_run_id),
                        str(data.analysis_run_id),
                        data.plugin_name,
                        PluginRunStatus.PENDING.value,
                        config_json,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                )

                row = connection.execute(
                    """
                    SELECT
                        id,
                        analysis_run_id,
                        plugin_name,
                        status,
                        configuration_json,
                        raw_output_path,
                        raw_output_sha256,
                        started_at,
                        completed_at,
                        error_message
                    FROM plugin_runs
                    WHERE id = ?
                    """,
                    (str(plugin_run_id),),
                ).fetchone()

        except sqlite3.Error as exc:
            raise PluginRunRepositoryError(
                "Could not create plugin run."
            ) from exc

        if row is None:
            raise PluginRunRepositoryError(
                "Plugin run was inserted but could not be retrieved."
            )

        return self._row_to_plugin_run(row)

    def get_by_id(self, plugin_run_id: UUID) -> PluginRun | None:
        """Return plugin run by ID, or None if it does not exist."""

        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    analysis_run_id,
                    plugin_name,
                    status,
                    configuration_json,
                    raw_output_path,
                    raw_output_sha256,
                    started_at,
                    completed_at,
                    error_message
                FROM plugin_runs
                WHERE id = ?
                """,
                (str(plugin_run_id),),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_plugin_run(row)

    def list_by_analysis_run(self, analysis_run_id: UUID) -> list[PluginRun]:
        """Return all plugin runs associated with an analysis run."""

        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    analysis_run_id,
                    plugin_name,
                    status,
                    configuration_json,
                    raw_output_path,
                    raw_output_sha256,
                    started_at,
                    completed_at,
                    error_message
                FROM plugin_runs
                WHERE analysis_run_id = ?
                ORDER BY plugin_name ASC
                """,
                (str(analysis_run_id),),
            ).fetchall()

        return [self._row_to_plugin_run(row) for row in rows]

    def mark_running(self, plugin_run_id: UUID) -> PluginRun:
        """Mark plugin run as running and set started_at to current UTC time."""
        now = datetime.now(UTC)
        return self._update_status(
            plugin_run_id,
            status=PluginRunStatus.RUNNING,
            started_at=now.isoformat(),
        )

    def mark_completed(
        self,
        plugin_run_id: UUID,
        raw_output_path: Path | None,
        raw_output_sha256: str | None,
    ) -> PluginRun:
        """Mark plugin run as completed with output details."""
        now = datetime.now(UTC)
        path_str = str(raw_output_path) if raw_output_path is not None else None
        return self._update_status(
            plugin_run_id,
            status=PluginRunStatus.COMPLETED,
            completed_at=now.isoformat(),
            raw_output_path=path_str,
            raw_output_sha256=raw_output_sha256,
        )

    def mark_failed(
        self,
        plugin_run_id: UUID,
        error_message: str,
        raw_output_path: Path | None = None,
        raw_output_sha256: str | None = None,
    ) -> PluginRun:
        """Mark plugin run as failed with error details."""
        now = datetime.now(UTC)
        path_str = str(raw_output_path) if raw_output_path is not None else None
        return self._update_status(
            plugin_run_id,
            status=PluginRunStatus.FAILED,
            completed_at=now.isoformat(),
            error_message=error_message,
            raw_output_path=path_str,
            raw_output_sha256=raw_output_sha256,
            update_error_message=True,
        )

    def mark_cancelled(self, plugin_run_id: UUID) -> PluginRun:
        """Mark plugin run as cancelled."""
        now = datetime.now(UTC)
        return self._update_status(
            plugin_run_id,
            status=PluginRunStatus.CANCELLED,
            completed_at=now.isoformat(),
        )

    def _update_status(
        self,
        plugin_run_id: UUID,
        status: PluginRunStatus,
        *,
        started_at: str | None = None,
        completed_at: str | None = None,
        error_message: str | None = None,
        raw_output_path: str | None = None,
        raw_output_sha256: str | None = None,
        update_error_message: bool = False,
    ) -> PluginRun:
        """Helper method to update status and execution metadata for a plugin run."""
        query_parts = ["status = ?"]
        params: list[str | None] = [status.value]

        if started_at is not None:
            query_parts.append("started_at = ?")
            params.append(started_at)

        if completed_at is not None:
            query_parts.append("completed_at = ?")
            params.append(completed_at)

        if raw_output_path is not None:
            query_parts.append("raw_output_path = ?")
            params.append(raw_output_path)

        if raw_output_sha256 is not None:
            query_parts.append("raw_output_sha256 = ?")
            params.append(raw_output_sha256)

        if update_error_message:
            query_parts.append("error_message = ?")
            params.append(error_message)

        params.append(str(plugin_run_id))
        set_clause = ", ".join(query_parts)

        with self.database.transaction() as connection:
            cursor = connection.execute(
                f"UPDATE plugin_runs SET {set_clause} WHERE id = ?",
                params,
            )

            if cursor.rowcount == 0:
                raise PluginRunNotFoundError(f"Plugin run not found: {plugin_run_id}")

            row = connection.execute(
                """
                SELECT
                    id,
                    analysis_run_id,
                    plugin_name,
                    status,
                    configuration_json,
                    raw_output_path,
                    raw_output_sha256,
                    started_at,
                    completed_at,
                    error_message
                FROM plugin_runs
                WHERE id = ?
                """,
                (str(plugin_run_id),),
            ).fetchone()

        if row is None:
            raise PluginRunNotFoundError(f"Plugin run not found: {plugin_run_id}")

        return self._row_to_plugin_run(row)

    @staticmethod
    def _row_to_plugin_run(row: sqlite3.Row) -> PluginRun:
        """Convert a SQLite row into a PluginRun model."""

        raw_path = (
            Path(row["raw_output_path"]) if row["raw_output_path"] is not None else None
        )
        try:
            config = json.loads(row["configuration_json"])
        except json.JSONDecodeError as exc:
            raise PluginRunRepositoryError(
                "Invalid JSON configuration payload in plugin run record."
            ) from exc

        return PluginRun(
            id=row["id"],
            analysis_run_id=row["analysis_run_id"],
            plugin_name=row["plugin_name"],
            status=row["status"],
            configuration=config,
            raw_output_path=raw_path,
            raw_output_sha256=row["raw_output_sha256"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            error_message=row["error_message"],
        )
