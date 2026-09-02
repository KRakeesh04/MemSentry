from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from uuid import UUID, uuid4

from memsentry.models.finding import Finding, FindingCreate, FindingSeverity
from memsentry.storage.database import Database


class FindingRepositoryError(RuntimeError):
    """Raised when a finding database operation fails."""


class FindingNotFoundError(FindingRepositoryError):
    """Raised when a requested finding is not found."""


class FindingRepository:
    """Store and retrieve detection findings."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, data: FindingCreate) -> Finding:
        """Create and return a new finding record."""

        finding_id = uuid4()
        now = datetime.now(UTC)

        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO findings (
                        id,
                        analysis_run_id,
                        rule_id,
                        title,
                        description,
                        severity,
                        confidence,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(finding_id),
                        str(data.analysis_run_id),
                        data.rule_id,
                        data.title,
                        data.description,
                        data.severity.value,
                        data.confidence,
                        now.isoformat(),
                    ),
                )

                row = connection.execute(
                    """
                    SELECT
                        id,
                        analysis_run_id,
                        rule_id,
                        title,
                        description,
                        severity,
                        confidence,
                        created_at
                    FROM findings
                    WHERE id = ?
                    """,
                    (str(finding_id),),
                ).fetchone()

        except sqlite3.Error as exc:
            raise FindingRepositoryError(
                "Could not create finding."
            ) from exc

        if row is None:
            raise FindingRepositoryError(
                "Finding was inserted but could not be retrieved."
            )

        return self._row_to_finding(row)

    def get_by_id(self, finding_id: UUID) -> Finding | None:
        """Return finding by ID, or None if it does not exist."""

        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    analysis_run_id,
                    rule_id,
                    title,
                    description,
                    severity,
                    confidence,
                    created_at
                FROM findings
                WHERE id = ?
                """,
                (str(finding_id),),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_finding(row)

    def list_by_analysis_run(self, analysis_run_id: UUID) -> list[Finding]:
        """Return all findings produced by an analysis run."""

        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    analysis_run_id,
                    rule_id,
                    title,
                    description,
                    severity,
                    confidence,
                    created_at
                FROM findings
                WHERE analysis_run_id = ?
                ORDER BY created_at ASC
                """,
                (str(analysis_run_id),),
            ).fetchall()

        return [self._row_to_finding(row) for row in rows]

    def list_by_severity(
        self,
        analysis_run_id: UUID,
        severity: FindingSeverity,
    ) -> list[Finding]:
        """Return findings for an analysis run filtered by severity level."""

        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    analysis_run_id,
                    rule_id,
                    title,
                    description,
                    severity,
                    confidence,
                    created_at
                FROM findings
                WHERE analysis_run_id = ? AND severity = ?
                ORDER BY created_at ASC
                """,
                (str(analysis_run_id), severity.value),
            ).fetchall()

        return [self._row_to_finding(row) for row in rows]

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        """Convert a SQLite row into a Finding model."""

        return Finding(
            id=row["id"],
            analysis_run_id=row["analysis_run_id"],
            rule_id=row["rule_id"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            confidence=row["confidence"],
            created_at=row["created_at"],
        )
