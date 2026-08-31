from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from uuid import UUID, uuid4

from memsentry.models.case import Case, CaseCreate, CaseStatus, CaseUpdate
from memsentry.storage.database import Database


class CaseRepositoryError(RuntimeError):
    """Raised when a case database operation fails."""


class DuplicateCaseNumberError(CaseRepositoryError):
    """Raised when a case number already exists."""


class CaseNotFoundError(CaseRepositoryError):
    """Raised when a requested case is not found."""


class CaseRepository:
    """Store and retrieve case records."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, case_data: CaseCreate) -> Case:
        """Create and return a new case."""

        case_id = uuid4()
        now = datetime.now(UTC)

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

    def get_by_id(self, case_id: UUID) -> Case | None:
        """Return a case by its ID, or None if it does not exist."""

        with self.database.connection() as connection:
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

        if row is None:
            return None

        return self._row_to_case(row)

    def get_by_case_number(
        self,
        case_number: str,
    ) -> Case | None:
        """Return a case by its case number, or None if it does not exist."""

        with self.database.connection() as connection:
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
                WHERE case_number = ?
                """,
                (case_number,),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_case(row)

    def list_all(self) -> list[Case]:
        """Return all cases stored in the database."""

        with self.database.connection() as connection:
            rows = connection.execute(
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
                ORDER BY created_at DESC
                """
            ).fetchall()

        return [self._row_to_case(row) for row in rows]

    def update_details(
        self,
        case_id: UUID,
        case_data: CaseUpdate,
    ) -> Case:
        """Update a case's name and description."""

        now = datetime.now(UTC)

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE cases
                SET
                    name = ?,
                    description = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    case_data.name,
                    case_data.description,
                    now.isoformat(),
                    str(case_id),
                ),
            )

            if cursor.rowcount == 0:
                raise CaseNotFoundError(f"Case not found: {case_id}")

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

        if row is None:
            raise CaseNotFoundError(f"Case not found: {case_id}")

        return self._row_to_case(row)

    def change_status(
        self,
        case_id: UUID,
        status: CaseStatus,
    ) -> Case:
        """Change a case's status."""

        now = datetime.now(UTC)

        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE cases
                SET
                    status = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    status.value,
                    now.isoformat(),
                    str(case_id),
                ),
            )

            if cursor.rowcount == 0:
                raise CaseNotFoundError(f"Case not found: {case_id}")

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

        if row is None:
            raise CaseNotFoundError(f"Case not found: {case_id}")

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
