from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from memsentry.models.evidence import (
    Evidence,
    EvidenceCreate,
    EvidenceOS,
    IntegrityStatus,
)
from memsentry.storage.database import Database


class EvidenceRepositoryError(RuntimeError):
    """Raised when an evidence database operation fails."""


class EvidenceNotFoundError(EvidenceRepositoryError):
    """Raised when requested evidence record is not found."""


class EvidenceRepository:
    """Store and retrieve evidence records."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, evidence_data: EvidenceCreate, *, case_relative: bool = False) -> Evidence:
        """Register a new evidence record."""

        evidence_id = uuid4()
        now = datetime.now(UTC)
        stored_path = str(evidence_data.file_path)
        if case_relative:
            case_directory = self._case_directory(evidence_data.case_id)
            try:
                stored_path = evidence_data.file_path.resolve().relative_to(case_directory).as_posix()
            except ValueError as exc:
                raise EvidenceRepositoryError("Portable evidence must be inside its case directory.") from exc
        os_val = (
            evidence_data.evidence_os.value
            if evidence_data.evidence_os is not None
            else None
        )

        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO evidence (
                        id,
                        case_id,
                        original_filename,
                        file_path,
                        path_base,
                        file_size_bytes,
                        sha256,
                        evidence_os,
                        integrity_status,
                        registered_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(evidence_id),
                        str(evidence_data.case_id),
                        evidence_data.original_filename,
                        stored_path,
                        "case" if case_relative else "original",
                        evidence_data.file_size_bytes,
                        evidence_data.sha256,
                        os_val,
                        IntegrityStatus.VERIFIED.value,
                        now.isoformat(),
                    ),
                )

                row = connection.execute(
                    """
                    SELECT *
                    FROM evidence
                    WHERE id = ?
                    """,
                    (str(evidence_id),),
                ).fetchone()

        except sqlite3.Error as exc:
            raise EvidenceRepositoryError(
                "Could not register evidence."
            ) from exc

        if row is None:
            raise EvidenceRepositoryError(
                "Evidence was inserted but could not be retrieved."
            )

        return self._row_to_evidence(row)

    def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        """Return evidence by its ID, or None if it does not exist."""

        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM evidence
                WHERE id = ?
                """,
                (str(evidence_id),),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_evidence(row)

    def list_by_case(self, case_id: UUID) -> list[Evidence]:
        """Return all evidence records associated with a case."""

        with self.database.connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM evidence
                WHERE case_id = ?
                ORDER BY registered_at ASC
                """,
                (str(case_id),),
            ).fetchall()

        return [self._row_to_evidence(row) for row in rows]

    def set_evidence_os(
        self,
        evidence_id: UUID,
        evidence_os: EvidenceOS,
    ) -> Evidence:
        """Update the detected evidence target operating system."""

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE evidence
                SET evidence_os = ?
                WHERE id = ?
                """,
                (evidence_os.value, str(evidence_id)),
            )

            if cursor.rowcount == 0:
                raise EvidenceNotFoundError(f"Evidence not found: {evidence_id}")

            row = connection.execute(
                """
                SELECT *
                FROM evidence
                WHERE id = ?
                """,
                (str(evidence_id),),
            ).fetchone()

        if row is None:
            raise EvidenceNotFoundError(f"Evidence not found: {evidence_id}")

        return self._row_to_evidence(row)

    def update_integrity_status(
        self,
        evidence_id: UUID,
        status: IntegrityStatus,
    ) -> Evidence:
        """Update the integrity status of evidence."""

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE evidence
                SET integrity_status = ?
                WHERE id = ?
                """,
                (status.value, str(evidence_id)),
            )

            if cursor.rowcount == 0:
                raise EvidenceNotFoundError(f"Evidence not found: {evidence_id}")

            row = connection.execute(
                """
                SELECT *
                FROM evidence
                WHERE id = ?
                """,
                (str(evidence_id),),
            ).fetchone()

        if row is None:
            raise EvidenceNotFoundError(f"Evidence not found: {evidence_id}")

        return self._row_to_evidence(row)

    def _case_directory(self, case_id: UUID) -> Path:
        return (self.database.database_path.parent / "cases" / str(case_id)).resolve()

    def _row_to_evidence(self, row: sqlite3.Row) -> Evidence:
        """Convert a SQLite row into an Evidence model."""

        file_path = Path(row["file_path"])
        if "path_base" in row.keys() and row["path_base"] == "case":  # noqa: SIM118 -- sqlite Row membership checks values.
            case_directory = self._case_directory(UUID(row["case_id"]))
            file_path = (case_directory / file_path).resolve()
            if not file_path.is_relative_to(case_directory):
                raise EvidenceRepositoryError("Stored evidence path escapes its case directory.")
        return Evidence(
            id=row["id"],
            case_id=row["case_id"],
            original_filename=row["original_filename"],
            file_path=file_path,
            file_size_bytes=row["file_size_bytes"],
            sha256=row["sha256"],
            evidence_os=row["evidence_os"],
            integrity_status=row["integrity_status"],
            registered_at=row["registered_at"],
        )
