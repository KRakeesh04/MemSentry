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

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE plugin_runs
                SET
                    status = ?,
                    started_at = ?
                WHERE id = ?
                """,
                (
                    PluginRunStatus.RUNNING.value,
                    now.isoformat(),
                    str(plugin_run_id),
                ),
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

    def mark_completed(
        self,
        plugin_run_id: UUID,
        raw_output_path: Path | None,
        raw_output_sha256: str | None,
    ) -> PluginRun:
        """Mark plugin run as completed with output details."""

        now = datetime.now(UTC)
        path_str = str(raw_output_path) if raw_output_path is not None else None

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE plugin_runs
                SET
                    status = ?,
                    completed_at = ?,
                    raw_output_path = ?,
                    raw_output_sha256 = ?
                WHERE id = ?
                """,
                (
                    PluginRunStatus.COMPLETED.value,
                    now.isoformat(),
                    path_str,
                    raw_output_sha256,
                    str(plugin_run_id),
                ),
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

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE plugin_runs
                SET
                    status = ?,
                    completed_at = ?,
                    error_message = ?,
                    raw_output_path = ?,
                    raw_output_sha256 = ?
                WHERE id = ?
                """,
                (
                    PluginRunStatus.FAILED.value,
                    now.isoformat(),
                    error_message,
                    path_str,
                    raw_output_sha256,
                    str(plugin_run_id),
                ),
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

    def mark_cancelled(self, plugin_run_id: UUID) -> PluginRun:
        """Mark plugin run as cancelled."""

        now = datetime.now(UTC)

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE plugin_runs
                SET
                    status = ?,
                    completed_at = ?
                WHERE id = ?
                """,
                (
                    PluginRunStatus.CANCELLED.value,
                    now.isoformat(),
                    str(plugin_run_id),
                ),
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
        config = json.loads(row["configuration_json"])

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
