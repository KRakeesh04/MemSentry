CREATE TABLE graph_revisions (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(id),
    name TEXT NOT NULL,
    investigator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    draft_json TEXT NOT NULL
);
CREATE INDEX graph_revisions_run ON graph_revisions(analysis_run_id, created_at);
CREATE TRIGGER graph_revisions_no_update BEFORE UPDATE ON graph_revisions
BEGIN SELECT RAISE(ABORT, 'Graph revisions are immutable'); END;
CREATE TRIGGER graph_revisions_no_delete BEFORE DELETE ON graph_revisions
BEGIN SELECT RAISE(ABORT, 'Graph revisions are immutable'); END;
