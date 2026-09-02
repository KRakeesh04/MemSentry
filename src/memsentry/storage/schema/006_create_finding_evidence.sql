CREATE TABLE finding_evidence (
    id TEXT PRIMARY KEY,

    finding_id TEXT NOT NULL,
    plugin_run_id TEXT NOT NULL,

    artifact_type TEXT,
    source_reference TEXT,

    supporting_data_json TEXT NOT NULL DEFAULT '{}',
    explanation TEXT NOT NULL,

    FOREIGN KEY (finding_id)
        REFERENCES findings(id)
        ON DELETE RESTRICT,

    FOREIGN KEY (plugin_run_id)
        REFERENCES plugin_runs(id)
        ON DELETE RESTRICT
);

CREATE INDEX idx_finding_evidence_finding_id
    ON finding_evidence(finding_id);

CREATE INDEX idx_finding_evidence_plugin_run_id
    ON finding_evidence(plugin_run_id);