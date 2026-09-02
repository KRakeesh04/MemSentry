CREATE TABLE plugin_runs (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,

    plugin_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',

    configuration_json TEXT NOT NULL DEFAULT '{}',

    raw_output_path TEXT,
    raw_output_sha256 TEXT,

    started_at TEXT,
    completed_at TEXT,

    error_message TEXT,

    FOREIGN KEY (analysis_run_id)
        REFERENCES analysis_runs(id)
        ON DELETE RESTRICT,

    CHECK (
        status IN (
            'pending',
            'running',
            'completed',
            'failed',
            'cancelled'
        )
    )
);

CREATE INDEX idx_plugin_runs_analysis_run_id
    ON plugin_runs(analysis_run_id);