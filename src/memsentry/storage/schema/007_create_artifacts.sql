CREATE TABLE artifacts (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    pid INTEGER,
    original_data_json TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    created_at TEXT NOT NULL,

    FOREIGN KEY (analysis_run_id) 
        REFERENCES analysis_runs (id)
        ON DELETE RESTRICT,
    
    FOREIGN KEY (plugin_run_id) 
        REFERENCES plugin_runs (id)
        ON DELETE RESTRICT
);

CREATE INDEX idx_artifacts_analysis_run_id
    ON artifacts(analysis_run_id);

CREATE INDEX idx_artifacts_plugin_run_id
    ON artifacts(plugin_run_id);