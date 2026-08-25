from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from memsentry.models.case import Case, CaseCreate, CaseStatus
from memsentry.storage.database import Database


class CaseRepositoryError(RuntimeError):
    """Raised when a case database operation fails."""


class DuplicateCaseNumberError(CaseRepositoryError):
    """Raised when a case number already exists."""


class CaseRepository:
    """Store and retrieve case records."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, case_data: CaseCreate) -> Case:
        """Create and return a new case."""

        case_id = uuid4()
        now = datetime.now(timezone.utc)

        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO cases (
                        id,
                        case_number,
                        name,
                        description,
                        status,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(case_id),
                        case_data.case_number,
                        case_data.name,
                        case_data.description,
                        CaseStatus.OPEN.value,
                        now.isoformat(),
                        now.isoformat(),
                    ),
                )

                row = connection.execute(
                    """
                    SELECT
                        id,
                        case_number,
                        name,
                        description,
                        status,
                        created_at,
                        updated_at
                    FROM cases
                    WHERE id = ?
                    """,
                    (str(case_id),),
                ).fetchone()

        except sqlite3.IntegrityError as exc:
            if "cases.case_number" in str(exc):
                raise DuplicateCaseNumberError(
                    f"Case number already exists: "
                    f"{case_data.case_number}"
                ) from exc

            raise CaseRepositoryError(
                "Could not create case."
            ) from exc

        if row is None:
            raise CaseRepositoryError(
                "Case was inserted but could not be retrieved."
            )

        return self._row_to_case(row)

    @staticmethod
    def _row_to_case(row: sqlite3.Row) -> Case:
        """Convert a SQLite row into a Case model."""

        return Case(
            id=row["id"],
            case_number=row["case_number"],
            name=row["name"],
            description=row["description"],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )