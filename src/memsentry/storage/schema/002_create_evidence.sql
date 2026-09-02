CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,

    original_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,

    sha256 TEXT NOT NULL,

    evidence_os TEXT,
    integrity_status TEXT NOT NULL DEFAULT 'verified',

    registered_at TEXT NOT NULL,

    FOREIGN KEY (case_id)
        REFERENCES cases(id)
        ON DELETE RESTRICT,

    CHECK (file_size_bytes >= 0),

    CHECK (
        evidence_os IS NULL
        OR evidence_os IN ('windows', 'linux', 'macos')
    ),

    CHECK (
        integrity_status IN (
            'verified',
            'modified',
            'unavailable'
        )
    )
);

CREATE INDEX idx_evidence_case_id
    ON evidence(case_id);