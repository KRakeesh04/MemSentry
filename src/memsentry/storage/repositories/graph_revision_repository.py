"""Append-only graph saves also retain investigator and timestamp for auditability."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from memsentry.models.graph_revision import GraphDraft, GraphRevision
from memsentry.storage.database import Database


class GraphRevisionRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, run_id: UUID, name: str, investigator: str, draft: GraphDraft) -> GraphRevision:
        if not name.strip() or not investigator.strip():
            raise ValueError("A revision name and investigator are required.")
        revision = GraphRevision(id=uuid4(), analysis_run_id=run_id, name=name.strip(),
                                 investigator=investigator.strip(), created_at=datetime.now(UTC),
                                 draft=draft.model_copy(deep=True))
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO graph_revisions VALUES (?, ?, ?, ?, ?, ?)",
                (str(revision.id), str(run_id), revision.name, revision.investigator,
                 revision.created_at.isoformat(), draft.model_dump_json()))
        return revision

    def list_by_run(self, run_id: UUID) -> list[GraphRevision]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM graph_revisions WHERE analysis_run_id = ? ORDER BY created_at DESC",
                (str(run_id),)).fetchall()
        return [GraphRevision(id=row["id"], analysis_run_id=row["analysis_run_id"],
                              name=row["name"], investigator=row["investigator"],
                              created_at=row["created_at"],
                              draft=GraphDraft.model_validate_json(row["draft_json"])) for row in rows]
