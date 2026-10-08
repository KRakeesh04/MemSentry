"""Persist immutable automated graph baselines, including empty graphs."""

import json
from datetime import UTC, datetime
from uuid import UUID

from memsentry.correlation.relationships import ArtifactRelationship
from memsentry.storage.database import Database


class RelationshipRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create_baseline(self, run_id: UUID, links: list[ArtifactRelationship]) -> None:
        with self.database.transaction() as connection:
            ids = {row["id"] for row in connection.execute(
                "SELECT id FROM artifacts WHERE analysis_run_id = ?", (str(run_id),))}
            if any(str(link.source_artifact_id) not in ids or str(link.target_artifact_id) not in ids
                   for link in links):
                raise ValueError("Relationship endpoints must be artifacts from the baseline run")
            connection.execute(
                "INSERT INTO relationship_baselines VALUES (?, ?, ?)",
                (str(run_id), "observed-v1", datetime.now(UTC).isoformat()))
            connection.executemany(
                "INSERT INTO artifact_relationships VALUES (?, ?, ?, ?, ?, ?)",
                [(str(run_id), str(link.source_artifact_id), str(link.target_artifact_id),
                  link.relationship_type, link.confidence, json.dumps(link.metadata))
                 for link in links])

    def load_baseline(self, run_id: UUID) -> list[ArtifactRelationship] | None:
        """None denotes a legacy run without a saved baseline; [] is a saved empty graph."""
        with self.database.connection() as connection:
            if not connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='relationship_baselines'"
            ).fetchone():
                return None
            if not connection.execute(
                "SELECT 1 FROM relationship_baselines WHERE analysis_run_id = ?", (str(run_id),)
            ).fetchone():
                return None
            rows = connection.execute(
                "SELECT * FROM artifact_relationships WHERE analysis_run_id = ? "
                "ORDER BY source_artifact_id, target_artifact_id, relationship_type", (str(run_id),)
            ).fetchall()
        return [ArtifactRelationship(
            UUID(row["source_artifact_id"]), UUID(row["target_artifact_id"]),
            row["relationship_type"], row["confidence"], json.loads(row["metadata_json"])
        ) for row in rows]
