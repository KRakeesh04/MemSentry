CREATE TABLE relationship_baselines (
    analysis_run_id TEXT PRIMARY KEY REFERENCES analysis_runs(id),
    algorithm_version TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE artifact_relationships (
    analysis_run_id TEXT NOT NULL REFERENCES relationship_baselines(analysis_run_id),
    source_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    target_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    relationship_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL,
    PRIMARY KEY (analysis_run_id, source_artifact_id, target_artifact_id, relationship_type)
);
