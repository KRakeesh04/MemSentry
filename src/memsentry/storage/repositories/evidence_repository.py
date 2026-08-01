from __future__ import annotations

import sqlite3
from uuid import uuid4

from memsentry.storage.database import Database
from memsentry.storage.repositories.case_repository import utc_now


class EvidenceRepository:
    """Store evidence metadata, hashes, and custody history."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def add_evidence(
        self,
        *,
        case_id: str,
        original_filename: str,
        evidence_path: str,
        file_size: int,
        evidence_type: str = "memory_image",
        file_format: str | None = None,
        operating_system: str | None = None,
        operating_system_version: str | None = None,
        architecture: str | None = None,
        acquisition_tool: str | None = None,
        acquisition_tool_version: str | None = None,
        acquisition_timestamp: str | None = None,
        acquisition_notes: str | None = None,
    ) -> str:
        """Add an evidence file and return its UUID."""
        evidence_id = str(uuid4())

        self.database.execute(
            """
            INSERT INTO evidence_files (
                id,
                case_id,
                original_filename,
                evidence_path,
                evidence_type,
                file_format,
                file_size,
                operating_system,
                operating_system_version,
                architecture,
                acquisition_tool,
                acquisition_tool_version,
                acquisition_timestamp,
                acquisition_notes,
                is_read_only,
                added_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                case_id,
                original_filename,
                evidence_path,
                evidence_type,
                file_format,
                file_size,
                operating_system,
                operating_system_version,
                architecture,
                acquisition_tool,
                acquisition_tool_version,
                acquisition_timestamp,
                acquisition_notes,
                1,
                utc_now(),
            ),
        )

        return evidence_id

    def get_evidence(self, evidence_id: str) -> sqlite3.Row | None:
        """Return one evidence record."""
        return self.database.fetch_one(
            "SELECT * FROM evidence_files WHERE id = ?",
            (evidence_id,),
        )

    def list_evidence_for_case(self, case_id: str) -> list[sqlite3.Row]:
        """Return all evidence files associated with a case."""
        return self.database.fetch_all(
            """
            SELECT *
            FROM evidence_files
            WHERE case_id = ?
            ORDER BY added_at
            """,
            (case_id,),
        )

    def update_evidence_path(
        self,
        evidence_id: str,
        evidence_path: str,
    ) -> bool:
        """Update the recorded path if evidence has been relocated."""
        affected = self.database.execute(
            """
            UPDATE evidence_files
            SET evidence_path = ?
            WHERE id = ?
            """,
            (evidence_path, evidence_id),
        )

        return affected > 0

    def record_hash(
        self,
        *,
        evidence_id: str,
        hash_value: str,
        hash_stage: str,
        file_size: int,
        algorithm: str = "SHA-256",
        analysis_run_id: str | None = None,
        duration_seconds: float | None = None,
        verified: bool | None = None,
    ) -> str:
        """Store an evidence hash calculation."""
        hash_id = str(uuid4())

        self.database.execute(
            """
            INSERT INTO evidence_hashes (
                id,
                evidence_id,
                analysis_run_id,
                algorithm,
                hash_value,
                hash_stage,
                file_size,
                duration_seconds,
                calculated_at,
                verified
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hash_id,
                evidence_id,
                analysis_run_id,
                algorithm,
                hash_value,
                hash_stage,
                file_size,
                duration_seconds,
                utc_now(),
                None if verified is None else int(verified),
            ),
        )

        return hash_id

    def get_latest_hash(
        self,
        evidence_id: str,
        hash_stage: str,
    ) -> sqlite3.Row | None:
        """Return the latest hash for a specified stage."""
        return self.database.fetch_one(
            """
            SELECT *
            FROM evidence_hashes
            WHERE evidence_id = ?
              AND hash_stage = ?
            ORDER BY calculated_at DESC
            LIMIT 1
            """,
            (evidence_id, hash_stage),
        )

    def list_hashes(self, evidence_id: str) -> list[sqlite3.Row]:
        """Return all hash records for evidence."""
        return self.database.fetch_all(
            """
            SELECT *
            FROM evidence_hashes
            WHERE evidence_id = ?
            ORDER BY calculated_at
            """,
            (evidence_id,),
        )

    def verify_pre_post_hash(
        self,
        evidence_id: str,
        analysis_run_id: str,
    ) -> bool | None:
        """
        Compare the latest pre-analysis and post-analysis hashes.

        Returns None if either hash is unavailable.
        """
        pre_hash = self.database.fetch_one(
            """
            SELECT hash_value
            FROM evidence_hashes
            WHERE evidence_id = ?
              AND analysis_run_id = ?
              AND hash_stage = 'pre_analysis'
            ORDER BY calculated_at DESC
            LIMIT 1
            """,
            (evidence_id, analysis_run_id),
        )

        post_hash = self.database.fetch_one(
            """
            SELECT hash_value
            FROM evidence_hashes
            WHERE evidence_id = ?
              AND analysis_run_id = ?
              AND hash_stage = 'post_analysis'
            ORDER BY calculated_at DESC
            LIMIT 1
            """,
            (evidence_id, analysis_run_id),
        )

        if pre_hash is None or post_hash is None:
            return None

        return str(pre_hash["hash_value"]).lower() == str(
            post_hash["hash_value"]
        ).lower()

    def add_custody_event(
        self,
        *,
        case_id: str,
        event_type: str,
        actor: str,
        description: str,
        evidence_id: str | None = None,
        location: str | None = None,
        event_timestamp: str | None = None,
    ) -> str:
        """Add a chain-of-custody event."""
        event_id = str(uuid4())

        self.database.execute(
            """
            INSERT INTO custody_events (
                id,
                case_id,
                evidence_id,
                event_type,
                actor,
                description,
                location,
                event_timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                case_id,
                evidence_id,
                event_type,
                actor,
                description,
                location,
                event_timestamp or utc_now(),
            ),
        )

        return event_id

    def list_custody_events(self, case_id: str) -> list[sqlite3.Row]:
        """Return custody events in chronological order."""
        return self.database.fetch_all(
            """
            SELECT *
            FROM custody_events
            WHERE case_id = ?
            ORDER BY event_timestamp
            """,
            (case_id,),
        )