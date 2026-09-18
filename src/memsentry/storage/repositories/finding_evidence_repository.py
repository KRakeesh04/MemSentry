from __future__ import annotations

import json
import sqlite3
from uuid import UUID, uuid4

from memsentry.models.finding_evidence import FindingEvidence, FindingEvidenceCreate
from memsentry.storage.database import Database


class FindingEvidenceRepositoryError(RuntimeError):
    """Raised when a finding evidence database operation fails."""


class FindingEvidenceNotFoundError(FindingEvidenceRepositoryError):
    """Raised when requested finding evidence is not found."""


class FindingEvidenceRepository:
    """Store and retrieve provenance evidence linking findings to plugin runs."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, data: FindingEvidenceCreate) -> FindingEvidence:
        """Create and return a new finding evidence record."""

        evidence_id = uuid4()
        supporting_json = json.dumps(data.supporting_data)

        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO finding_evidence (
                        id,
                        finding_id,
                        plugin_run_id,
                        artifact_type,
                        source_reference,
                        supporting_data_json,
                        explanation
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(evidence_id),
                        str(data.finding_id),
                        str(data.plugin_run_id),
                        data.artifact_type,
                        data.source_reference,
                        supporting_json,
                        data.explanation,
                    ),
                )

                row = connection.execute(
                    """
                    SELECT
                        id,
                        finding_id,
                        plugin_run_id,
                        artifact_type,
                        source_reference,
                        supporting_data_json,
                        explanation
                    FROM finding_evidence
                    WHERE id = ?
                    """,
                    (str(evidence_id),),
                ).fetchone()

        except sqlite3.Error as exc:
            raise FindingEvidenceRepositoryError(
                "Could not create finding evidence."
            ) from exc

        if row is None:
            raise FindingEvidenceRepositoryError(
                "Finding evidence was inserted but could not be retrieved."
            )

        return self._row_to_finding_evidence(row)

    def get_by_id(self, finding_evidence_id: UUID) -> FindingEvidence | None:
        """Return finding evidence by ID, or None if it does not exist."""

        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    finding_id,
                    plugin_run_id,
                    artifact_type,
                    source_reference,
                    supporting_data_json,
                    explanation
                FROM finding_evidence
                WHERE id = ?
                """,
                (str(finding_evidence_id),),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_finding_evidence(row)

    def list_by_finding(self, finding_id: UUID) -> list[FindingEvidence]:
        """Return all provenance evidence items linked to a finding."""

        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    finding_id,
                    plugin_run_id,
                    artifact_type,
                    source_reference,
                    supporting_data_json,
                    explanation
                FROM finding_evidence
                WHERE finding_id = ?
                """,
                (str(finding_id),),
            ).fetchall()

        return [self._row_to_finding_evidence(row) for row in rows]

    @staticmethod
    def _row_to_finding_evidence(row: sqlite3.Row) -> FindingEvidence:
        """Convert a SQLite row into a FindingEvidence model."""

        try:
            supporting_data = json.loads(row["supporting_data_json"])
        except json.JSONDecodeError as exc:
            raise FindingEvidenceRepositoryError(
                "Invalid JSON supporting data payload in finding evidence record."
            ) from exc

        return FindingEvidence(
            id=row["id"],
            finding_id=row["finding_id"],
            plugin_run_id=row["plugin_run_id"],
            artifact_type=row["artifact_type"],
            source_reference=row["source_reference"],
            supporting_data=supporting_data,
            explanation=row["explanation"],
        )
