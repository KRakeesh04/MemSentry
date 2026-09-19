"""Append-only operation and integrity checkpoint history."""

from datetime import UTC, datetime

from memsentry.storage.database import Database


class WorkflowRepository:
    def __init__(self, database: Database):
        self.database = database

    def record(
        self,
        evidence_id,
        run_id,
        stage,
        phase,
        status,
        progress=0,
        expected=None,
        actual=None,
        message="",
    ):
        with self.database.transaction() as connection:
            connection.execute(
                """INSERT INTO workflow_events
                (evidence_id, analysis_run_id, stage, phase, status, progress,
                 expected_sha256, actual_sha256, message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(evidence_id),
                    str(run_id) if run_id else None,
                    stage,
                    phase,
                    status,
                    progress,
                    expected,
                    actual,
                    message,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def list_events(self, evidence_id, run_id=None):
        with self.database.connection() as connection:
            # Old workspaces are readable without migrating them just to display a page.
            if not connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='workflow_events'"
            ).fetchone():
                return []
            rows = connection.execute(
                """SELECT * FROM workflow_events WHERE evidence_id = ?
                AND (analysis_run_id IS NULL OR analysis_run_id = ?) ORDER BY id""",
                (str(evidence_id), str(run_id) if run_id else None),
            ).fetchall()
        return [dict(row) for row in rows]
