from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

from memsentry.storage.database import Database


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class CaseRepository:
    """Store and retrieve forensic cases and analysis runs."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create_case(
        self,
        *,
        case_number: str,
        title: str,
        investigator_name: str,
        case_directory: str,
        description: str | None = None,
        organisation: str | None = None,
    ) -> str:
        """Create a new forensic case and return its UUID."""
        case_id = str(uuid4())
        timestamp = utc_now()

        self.database.execute(
            """
            INSERT INTO cases (
                id,
                case_number,
                title,
                description,
                investigator_name,
                organisation,
                status,
                created_at,
                updated_at,
                case_directory
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                case_number,
                title,
                description,
                investigator_name,
                organisation,
                "created",
                timestamp,
                timestamp,
                case_directory,
            ),
        )

        return case_id

    def get_case(self, case_id: str) -> sqlite3.Row | None:
        """Return one case by its UUID."""
        return self.database.fetch_one(
            "SELECT * FROM cases WHERE id = ?",
            (case_id,),
        )

    def get_case_by_number(self, case_number: str) -> sqlite3.Row | None:
        """Return one case by its human-readable case number."""
        return self.database.fetch_one(
            "SELECT * FROM cases WHERE case_number = ?",
            (case_number,),
        )

    def list_cases(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[sqlite3.Row]:
        """List cases, optionally filtered by status."""
        if status is not None:
            return self.database.fetch_all(
                """
                SELECT *
                FROM cases
                WHERE status = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (status, limit, offset),
            )

        return self.database.fetch_all(
            """
            SELECT *
            FROM cases
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )

    def update_case(
        self,
        case_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        investigator_name: str | None = None,
        organisation: str | None = None,
        notes: str | None = None,
    ) -> bool:
        """Update editable case fields."""
        current = self.get_case(case_id)

        if current is None:
            return False

        affected = self.database.execute(
            """
            UPDATE cases
            SET
                title = ?,
                description = ?,
                investigator_name = ?,
                organisation = ?,
                notes = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                title if title is not None else current["title"],
                description if description is not None else current["description"],
                investigator_name
                if investigator_name is not None
                else current["investigator_name"],
                organisation
                if organisation is not None
                else current["organisation"],
                notes if notes is not None else current["notes"],
                utc_now(),
                case_id,
            ),
        )

        return affected > 0

    def update_case_status(self, case_id: str, status: str) -> bool:
        """Update the lifecycle status of a case."""
        affected = self.database.execute(
            """
            UPDATE cases
            SET status = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, utc_now(), case_id),
        )

        return affected > 0

    def archive_case(self, case_id: str) -> bool:
        """Mark a case as archived."""
        return self.update_case_status(case_id, "archived")

    def delete_case(self, case_id: str) -> bool:
        """
        Delete a case database record.

        The application should separately confirm before deleting case files.
        """
        affected = self.database.execute(
            "DELETE FROM cases WHERE id = ?",
            (case_id,),
        )

        return affected > 0

    def create_analysis_run(
        self,
        *,
        case_id: str,
        evidence_id: str,
        application_version: str,
        selected_plugins_json: str,
        configuration_json: str = "{}",
        python_version: str | None = None,
        volatility_version: str | None = None,
        rule_set_version: str | None = None,
        worker_protocol_version: str | None = None,
    ) -> str:
        """Create a new analysis-run record."""
        run_id = str(uuid4())

        row = self.database.fetch_one(
            """
            SELECT COALESCE(MAX(run_number), 0) + 1 AS next_number
            FROM analysis_runs
            WHERE case_id = ?
            """,
            (case_id,),
        )

        run_number = int(row["next_number"]) if row else 1

        self.database.execute(
            """
            INSERT INTO analysis_runs (
                id,
                case_id,
                evidence_id,
                run_number,
                status,
                application_version,
                python_version,
                volatility_version,
                rule_set_version,
                worker_protocol_version,
                configuration_json,
                selected_plugins_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                case_id,
                evidence_id,
                run_number,
                "pending",
                application_version,
                python_version,
                volatility_version,
                rule_set_version,
                worker_protocol_version,
                configuration_json,
                selected_plugins_json,
            ),
        )

        return run_id

    def get_analysis_run(self, run_id: str) -> sqlite3.Row | None:
        """Return one analysis run."""
        return self.database.fetch_one(
            "SELECT * FROM analysis_runs WHERE id = ?",
            (run_id,),
        )

    def list_analysis_runs(self, case_id: str) -> list[sqlite3.Row]:
        """Return all analysis runs for a case."""
        return self.database.fetch_all(
            """
            SELECT *
            FROM analysis_runs
            WHERE case_id = ?
            ORDER BY run_number DESC
            """,
            (case_id,),
        )

    def start_analysis_run(self, run_id: str) -> bool:
        """Mark an analysis run as started."""
        affected = self.database.execute(
            """
            UPDATE analysis_runs
            SET status = 'running', started_at = ?
            WHERE id = ?
            """,
            (utc_now(), run_id),
        )

        return affected > 0

    def complete_analysis_run(
        self,
        run_id: str,
        *,
        status: str = "completed",
        duration_seconds: float | None = None,
        peak_memory_bytes: int | None = None,
    ) -> bool:
        """Complete, partially complete, fail, or cancel an analysis run."""
        affected = self.database.execute(
            """
            UPDATE analysis_runs
            SET
                status = ?,
                completed_at = ?,
                analysis_duration_seconds = ?,
                peak_memory_bytes = ?
            WHERE id = ?
            """,
            (
                status,
                utc_now(),
                duration_seconds,
                peak_memory_bytes,
                run_id,
            ),
        )

        return affected > 0