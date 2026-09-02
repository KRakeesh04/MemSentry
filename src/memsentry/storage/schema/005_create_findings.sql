CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,

    rule_id TEXT NOT NULL,

    title TEXT NOT NULL,
    description TEXT NOT NULL,

    severity TEXT NOT NULL,
    confidence REAL,

    created_at TEXT NOT NULL,

    FOREIGN KEY (analysis_run_id)
        REFERENCES analysis_runs(id)
        ON DELETE RESTRICT,

    CHECK (
        severity IN (
            'informational',
            'low',
            'medium',
            'high',
            'critical'
        )
    ),

    CHECK (
        confidence IS NULL
        OR (
            confidence >= 0.0
            AND confidence <= 1.0
        )
    )
);

CREATE INDEX idx_findings_analysis_run_id
    ON findings(analysis_run_id);

CREATE INDEX idx_findings_severity
    ON findings(severity);