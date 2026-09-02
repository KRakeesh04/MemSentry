from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from uuid import UUID, uuid4

from memsentry.models.analysis_run import (
    AnalysisRun,
    AnalysisRunCreate,
    AnalysisRunStatus,
)
from memsentry.storage.database import Database


class AnalysisRunRepositoryError(RuntimeError):
    """Raised when an analysis run database operation fails."""


class AnalysisRunNotFoundError(AnalysisRunRepositoryError):
    """Raised when a requested analysis run record is not found."""


class AnalysisRunRepository:
    """Store and retrieve analysis run records."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, data: AnalysisRunCreate) -> AnalysisRun:
        """Create and return a new analysis run in pending state."""

        analysis_run_id = uuid4()
        now = datetime.now(UTC)

        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO analysis_runs (
                        id,
                        evidence_id,
                        status,
                        application_version,
                        volatility_version,
                        host_os,
                        created_at,
                        started_at,
                        completed_at,
                        error_message
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(analysis_run_id),
                        str(data.evidence_id),
                        AnalysisRunStatus.PENDING.value,
                        data.application_version,
                        data.volatility_version,
                        data.host_os.value,
                        now.isoformat(),
                        None,
                        None,
                        None,
                    ),
                )

                row = connection.execute(
                    """
                    SELECT
                        id,
                        evidence_id,
                        status,
                        application_version,
                        volatility_version,
                        host_os,
                        created_at,
                        started_at,
                        completed_at,
                        error_message
                    FROM analysis_runs
                    WHERE id = ?
                    """,
                    (str(analysis_run_id),),
                ).fetchone()

        except sqlite3.Error as exc:
            raise AnalysisRunRepositoryError(
                "Could not create analysis run."
            ) from exc

        if row is None:
            raise AnalysisRunRepositoryError(
                "Analysis run was inserted but could not be retrieved."
            )

        return self._row_to_analysis_run(row)

    def get_by_id(self, analysis_run_id: UUID) -> AnalysisRun | None:
        """Return analysis run by ID, or None if it does not exist."""

        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    evidence_id,
                    status,
                    application_version,
                    volatility_version,
                    host_os,
                    created_at,
                    started_at,
                    completed_at,
                    error_message
                FROM analysis_runs
                WHERE id = ?
                """,
                (str(analysis_run_id),),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_analysis_run(row)

    def list_by_evidence(self, evidence_id: UUID) -> list[AnalysisRun]:
        """Return all analysis runs associated with an evidence record."""

        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    evidence_id,
                    status,
                    application_version,
                    volatility_version,
                    host_os,
                    created_at,
                    started_at,
                    completed_at,
                    error_message
                FROM analysis_runs
                WHERE evidence_id = ?
                ORDER BY created_at DESC
                """,
                (str(evidence_id),),
            ).fetchall()

        return [self._row_to_analysis_run(row) for row in rows]

    def mark_running(self, analysis_run_id: UUID) -> AnalysisRun:
        """Mark analysis run as running and set started_at to current UTC time."""

        now = datetime.now(UTC)

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_runs
                SET
                    status = ?,
                    started_at = ?
                WHERE id = ?
                """,
                (
                    AnalysisRunStatus.RUNNING.value,
                    now.isoformat(),
                    str(analysis_run_id),
                ),
            )

            if cursor.rowcount == 0:
                raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

            row = connection.execute(
                """
                SELECT
                    id,
                    evidence_id,
                    status,
                    application_version,
                    volatility_version,
                    host_os,
                    created_at,
                    started_at,
                    completed_at,
                    error_message
                FROM analysis_runs
                WHERE id = ?
                """,
                (str(analysis_run_id),),
            ).fetchone()

        if row is None:
            raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

        return self._row_to_analysis_run(row)

    def mark_completed(self, analysis_run_id: UUID) -> AnalysisRun:
        """Mark analysis run as completed and set completed_at to current UTC time."""

        now = datetime.now(UTC)

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_runs
                SET
                    status = ?,
                    completed_at = ?
                WHERE id = ?
                """,
                (
                    AnalysisRunStatus.COMPLETED.value,
                    now.isoformat(),
                    str(analysis_run_id),
                ),
            )

            if cursor.rowcount == 0:
                raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

            row = connection.execute(
                """
                SELECT
                    id,
                    evidence_id,
                    status,
                    application_version,
                    volatility_version,
                    host_os,
                    created_at,
                    started_at,
                    completed_at,
                    error_message
                FROM analysis_runs
                WHERE id = ?
                """,
                (str(analysis_run_id),),
            ).fetchone()

        if row is None:
            raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

        return self._row_to_analysis_run(row)

    def mark_completed_with_errors(
        self,
        analysis_run_id: UUID,
        error_message: str | None = None,
    ) -> AnalysisRun:
        """Mark analysis run as completed with errors and record error details."""

        now = datetime.now(UTC)

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_runs
                SET
                    status = ?,
                    completed_at = ?,
                    error_message = ?
                WHERE id = ?
                """,
                (
                    AnalysisRunStatus.COMPLETED_WITH_ERRORS.value,
                    now.isoformat(),
                    error_message,
                    str(analysis_run_id),
                ),
            )

            if cursor.rowcount == 0:
                raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

            row = connection.execute(
                """
                SELECT
                    id,
                    evidence_id,
                    status,
                    application_version,
                    volatility_version,
                    host_os,
                    created_at,
                    started_at,
                    completed_at,
                    error_message
                FROM analysis_runs
                WHERE id = ?
                """,
                (str(analysis_run_id),),
            ).fetchone()

        if row is None:
            raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

        return self._row_to_analysis_run(row)

    def mark_failed(
        self,
        analysis_run_id: UUID,
        error_message: str,
    ) -> AnalysisRun:
        """Mark analysis run as failed with error message."""

        now = datetime.now(UTC)

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_runs
                SET
                    status = ?,
                    completed_at = ?,
                    error_message = ?
                WHERE id = ?
                """,
                (
                    AnalysisRunStatus.FAILED.value,
                    now.isoformat(),
                    error_message,
                    str(analysis_run_id),
                ),
            )

            if cursor.rowcount == 0:
                raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

            row = connection.execute(
                """
                SELECT
                    id,
                    evidence_id,
                    status,
                    application_version,
                    volatility_version,
                    host_os,
                    created_at,
                    started_at,
                    completed_at,
                    error_message
                FROM analysis_runs
                WHERE id = ?
                """,
                (str(analysis_run_id),),
            ).fetchone()

        if row is None:
            raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

        return self._row_to_analysis_run(row)

    def mark_cancelled(self, analysis_run_id: UUID) -> AnalysisRun:
        """Mark analysis run as cancelled."""

        now = datetime.now(UTC)

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_runs
                SET
                    status = ?,
                    completed_at = ?
                WHERE id = ?
                """,
                (
                    AnalysisRunStatus.CANCELLED.value,
                    now.isoformat(),
                    str(analysis_run_id),
                ),
            )

            if cursor.rowcount == 0:
                raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

            row = connection.execute(
                """
                SELECT
                    id,
                    evidence_id,
                    status,
                    application_version,
                    volatility_version,
                    host_os,
                    created_at,
                    started_at,
                    completed_at,
                    error_message
                FROM analysis_runs
                WHERE id = ?
                """,
                (str(analysis_run_id),),
            ).fetchone()

        if row is None:
            raise AnalysisRunNotFoundError(f"Analysis run not found: {analysis_run_id}")

        return self._row_to_analysis_run(row)

    @staticmethod
    def _row_to_analysis_run(row: sqlite3.Row) -> AnalysisRun:
        """Convert a SQLite row into an AnalysisRun model."""

        return AnalysisRun(
            id=row["id"],
            evidence_id=row["evidence_id"],
            status=row["status"],
            application_version=row["application_version"],
            volatility_version=row["volatility_version"],
            host_os=row["host_os"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            error_message=row["error_message"],
        )
