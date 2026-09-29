CREATE TABLE workflow_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    analysis_run_id TEXT REFERENCES analysis_runs(id),
    stage TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('before', 'operation', 'after')),
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    progress INTEGER NOT NULL CHECK (progress BETWEEN 0 AND 100),
    expected_sha256 TEXT,
    actual_sha256 TEXT,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX workflow_events_evidence_run ON workflow_events(evidence_id, analysis_run_id, id);
