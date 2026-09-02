CREATE TABLE analysis_runs (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'pending',

    application_version TEXT NOT NULL,
    volatility_version TEXT NOT NULL,
    host_os TEXT NOT NULL,

    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,

    error_message TEXT,

    FOREIGN KEY (evidence_id)
        REFERENCES evidence(id)
        ON DELETE RESTRICT,

    CHECK (
        status IN (
            'pending',
            'running',
            'completed',
            'completed_with_errors',
            'failed',
            'cancelled'
        )
    ),

    CHECK (
        host_os IN (
            'windows',
            'linux',
            'macos'
        )
    )
);

CREATE INDEX idx_analysis_runs_evidence_id
    ON analysis_runs(evidence_id);