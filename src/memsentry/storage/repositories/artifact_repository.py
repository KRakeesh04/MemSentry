from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from typing import Any
from uuid import uuid4

from memsentry.storage.database import Database


class ArtifactRepository:
    """Store and query normalized memory-forensics artifacts."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def add_process(
        self,
        *,
        analysis_run_id: str,
        pid: int,
        process_name: str,
        ppid: int | None = None,
        command_line: str | None = None,
        plugin_run_id: str | None = None,
        created_at: str | None = None,
        exited_at: str | None = None,
        original_data: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> str:
        """Insert a normalized process artifact."""
        process_id = str(uuid4())

        self.database.execute(
            """
            INSERT INTO processes (
                id,
                analysis_run_id,
                plugin_run_id,
                pid,
                ppid,
                process_name,
                command_line,
                created_at,
                exited_at,
                original_data_json,
                provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                process_id,
                analysis_run_id,
                plugin_run_id,
                pid,
                ppid,
                process_name,
                command_line,
                created_at,
                exited_at,
                json.dumps(original_data or {}),
                json.dumps(provenance or {}),
            ),
        )

        return process_id

    def add_processes(self, rows: Iterable[tuple[Any, ...]]) -> int:
        """Insert multiple already-normalized process rows."""
        return self.database.execute_many(
            """
            INSERT INTO processes (
                id,
                analysis_run_id,
                plugin_run_id,
                pid,
                ppid,
                process_name,
                command_line,
                original_data_json,
                provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            list(rows),
        )

    def get_process(self, process_id: str) -> sqlite3.Row | None:
        """Return one process by artifact UUID."""
        return self.database.fetch_one(
            "SELECT * FROM processes WHERE id = ?",
            (process_id,),
        )

    def get_process_by_pid(
        self,
        analysis_run_id: str,
        pid: int,
    ) -> sqlite3.Row | None:
        """Return a process by PID within one analysis run."""
        return self.database.fetch_one(
            """
            SELECT *
            FROM processes
            WHERE analysis_run_id = ?
              AND pid = ?
            ORDER BY created_at
            LIMIT 1
            """,
            (analysis_run_id, pid),
        )

    def list_processes(
        self,
        analysis_run_id: str,
        *,
        risk_level: str | None = None,
        search_text: str | None = None,
    ) -> list[sqlite3.Row]:
        """List processes with optional filtering."""
        if risk_level is not None:
            return self.database.fetch_all(
                """
                SELECT *
                FROM processes
                WHERE analysis_run_id = ?
                  AND risk_level = ?
                ORDER BY risk_score DESC, pid
                """,
                (analysis_run_id, risk_level),
            )

        if search_text is not None:
            pattern = f"%{search_text}%"

            return self.database.fetch_all(
                """
                SELECT *
                FROM processes
                WHERE analysis_run_id = ?
                  AND (
                      process_name LIKE ?
                      OR command_line LIKE ?
                      OR CAST(pid AS TEXT) LIKE ?
                  )
                ORDER BY risk_score DESC, pid
                """,
                (analysis_run_id, pattern, pattern, pattern),
            )

        return self.database.fetch_all(
            """
            SELECT *
            FROM processes
            WHERE analysis_run_id = ?
            ORDER BY risk_score DESC, pid
            """,
            (analysis_run_id,),
        )

    def add_memory_region(
        self,
        *,
        analysis_run_id: str,
        pid: int,
        start_address: str,
        end_address: str,
        process_id: str | None = None,
        plugin_run_id: str | None = None,
        region_size: int | None = None,
        protection: str | None = None,
        is_private: bool | None = None,
        is_executable: bool | None = None,
        is_writable: bool | None = None,
        mapped_file: str | None = None,
        original_data: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> str:
        """Insert a normalized memory-region artifact."""
        region_id = str(uuid4())

        self.database.execute(
            """
            INSERT INTO memory_regions (
                id,
                analysis_run_id,
                plugin_run_id,
                process_id,
                pid,
                start_address,
                end_address,
                region_size,
                protection,
                is_private,
                is_executable,
                is_writable,
                mapped_file,
                original_data_json,
                provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                region_id,
                analysis_run_id,
                plugin_run_id,
                process_id,
                pid,
                start_address,
                end_address,
                region_size,
                protection,
                None if is_private is None else int(is_private),
                None if is_executable is None else int(is_executable),
                None if is_writable is None else int(is_writable),
                mapped_file,
                json.dumps(original_data or {}),
                json.dumps(provenance or {}),
            ),
        )

        return region_id

    def list_memory_regions(
        self,
        analysis_run_id: str,
        *,
        process_id: str | None = None,
        suspicious_only: bool = False,
    ) -> list[sqlite3.Row]:
        """Return memory regions, optionally limited to suspicious regions."""
        if process_id is not None and suspicious_only:
            return self.database.fetch_all(
                """
                SELECT *
                FROM memory_regions
                WHERE analysis_run_id = ?
                  AND process_id = ?
                  AND is_private = 1
                  AND is_executable = 1
                ORDER BY start_address
                """,
                (analysis_run_id, process_id),
            )

        if process_id is not None:
            return self.database.fetch_all(
                """
                SELECT *
                FROM memory_regions
                WHERE analysis_run_id = ?
                  AND process_id = ?
                ORDER BY start_address
                """,
                (analysis_run_id, process_id),
            )

        return self.database.fetch_all(
            """
            SELECT *
            FROM memory_regions
            WHERE analysis_run_id = ?
            ORDER BY pid, start_address
            """,
            (analysis_run_id,),
        )

    def add_network_connection(
        self,
        *,
        analysis_run_id: str,
        pid: int | None,
        protocol: str | None,
        local_address: str | None,
        local_port: int | None,
        remote_address: str | None,
        remote_port: int | None,
        process_id: str | None = None,
        plugin_run_id: str | None = None,
        connection_state: str | None = None,
        original_data: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> str:
        """Insert a normalized network-connection artifact."""
        connection_id = str(uuid4())

        self.database.execute(
            """
            INSERT INTO network_connections (
                id,
                analysis_run_id,
                plugin_run_id,
                process_id,
                pid,
                protocol,
                local_address,
                local_port,
                remote_address,
                remote_port,
                connection_state,
                original_data_json,
                provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                connection_id,
                analysis_run_id,
                plugin_run_id,
                process_id,
                pid,
                protocol,
                local_address,
                local_port,
                remote_address,
                remote_port,
                connection_state,
                json.dumps(original_data or {}),
                json.dumps(provenance or {}),
            ),
        )

        return connection_id

    def list_network_connections(
        self,
        analysis_run_id: str,
        *,
        process_id: str | None = None,
    ) -> list[sqlite3.Row]:
        """Return network connections for a run or process."""
        if process_id is not None:
            return self.database.fetch_all(
                """
                SELECT *
                FROM network_connections
                WHERE analysis_run_id = ?
                  AND process_id = ?
                ORDER BY remote_address, remote_port
                """,
                (analysis_run_id, process_id),
            )

        return self.database.fetch_all(
            """
            SELECT *
            FROM network_connections
            WHERE analysis_run_id = ?
            ORDER BY pid, remote_address, remote_port
            """,
            (analysis_run_id,),
        )

    def add_signature_match(
        self,
        *,
        analysis_run_id: str,
        rule_name: str,
        process_id: str | None = None,
        memory_region_id: str | None = None,
        plugin_run_id: str | None = None,
        pid: int | None = None,
        namespace: str | None = None,
        match_address: str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        original_data: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> str:
        """Insert a normalized YARA or signature match."""
        match_id = str(uuid4())

        self.database.execute(
            """
            INSERT INTO signature_matches (
                id,
                analysis_run_id,
                plugin_run_id,
                process_id,
                memory_region_id,
                pid,
                rule_name,
                namespace,
                tags_json,
                metadata_json,
                match_address,
                original_data_json,
                provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                match_id,
                analysis_run_id,
                plugin_run_id,
                process_id,
                memory_region_id,
                pid,
                rule_name,
                namespace,
                json.dumps(tags or []),
                json.dumps(metadata or {}),
                match_address,
                json.dumps(original_data or {}),
                json.dumps(provenance or {}),
            ),
        )

        return match_id

    def add_relationship(
        self,
        *,
        analysis_run_id: str,
        source_artifact_id: str,
        source_artifact_type: str,
        target_artifact_id: str,
        target_artifact_type: str,
        relationship_type: str,
        relationship_origin: str,
        confidence: float | None = None,
        description: str | None = None,
        supporting_rule_id: str | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> str:
        """Create an observed, derived, or inferred relationship."""
        relationship_id = str(uuid4())

        self.database.execute(
            """
            INSERT INTO evidence_relationships (
                id,
                analysis_run_id,
                source_artifact_id,
                source_artifact_type,
                target_artifact_id,
                target_artifact_type,
                relationship_type,
                relationship_origin,
                confidence,
                description,
                supporting_rule_id,
                provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                relationship_id,
                analysis_run_id,
                source_artifact_id,
                source_artifact_type,
                target_artifact_id,
                target_artifact_type,
                relationship_type,
                relationship_origin,
                confidence,
                description,
                supporting_rule_id,
                json.dumps(provenance or {}),
            ),
        )

        return relationship_id

    def list_relationships(
        self,
        analysis_run_id: str,
        *,
        artifact_id: str | None = None,
    ) -> list[sqlite3.Row]:
        """Return graph relationships for a run or artifact."""
        if artifact_id is not None:
            return self.database.fetch_all(
                """
                SELECT *
                FROM evidence_relationships
                WHERE analysis_run_id = ?
                  AND (
                      source_artifact_id = ?
                      OR target_artifact_id = ?
                  )
                """,
                (analysis_run_id, artifact_id, artifact_id),
            )

        return self.database.fetch_all(
            """
            SELECT *
            FROM evidence_relationships
            WHERE analysis_run_id = ?
            """,
            (analysis_run_id,),
        )

    def update_process_score(
        self,
        process_id: str,
        *,
        risk_score: float,
        risk_level: str,
        confidence_level: str | None = None,
    ) -> bool:
        """Update process-level scoring after correlation."""
        affected = self.database.execute(
            """
            UPDATE processes
            SET
                risk_score = ?,
                risk_level = ?,
                confidence_level = ?
            WHERE id = ?
            """,
            (
                risk_score,
                risk_level,
                confidence_level,
                process_id,
            ),
        )

        return affected > 0

    def count_artifacts(self, analysis_run_id: str) -> dict[str, int]:
        """Return artifact totals for dashboard summaries."""
        result: dict[str, int] = {}

        tables = {
            "processes": "processes",
            "threads": "threads",
            "memory_regions": "memory_regions",
            "modules": "modules",
            "network_connections": "network_connections",
            "signature_matches": "signature_matches",
        }

        for key, table in tables.items():
            row = self.database.fetch_one(
                f"""
                SELECT COUNT(*) AS count
                FROM {table}
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            )

            result[key] = int(row["count"]) if row else 0

        return result