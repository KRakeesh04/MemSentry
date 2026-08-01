-- ============================================================
-- MemSentry SQLite Database Schema
-- Version: 0.1.0
-- Database: SQLite 3
-- ============================================================

PRAGMA foreign_keys = ON;

PRAGMA journal_mode = WAL;

PRAGMA synchronous = NORMAL;

BEGIN TRANSACTION;

-- ============================================================
-- Schema metadata
-- ============================================================

CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT
    OR IGNORE INTO schema_metadata (key, value)
VALUES ('schema_version', '0.1.0'),
    ('application', 'MemSentry');

-- ============================================================
-- Cases
-- ============================================================

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    case_number TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT,
    investigator_name TEXT NOT NULL,
    organisation TEXT,
    status TEXT NOT NULL DEFAULT 'created' CHECK (
        status IN (
            'created',
            'ready',
            'analysing',
            'completed',
            'partial',
            'failed',
            'cancelled',
            'archived'
        )
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    case_directory TEXT NOT NULL,
    notes TEXT
);

-- ============================================================
-- Evidence files
-- ============================================================

CREATE TABLE IF NOT EXISTS evidence_files (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    evidence_path TEXT NOT NULL,
    evidence_type TEXT NOT NULL DEFAULT 'memory_image' CHECK (
        evidence_type IN (
            'memory_image',
            'crash_dump',
            'hibernation_file',
            'other'
        )
    ),
    file_format TEXT,
    file_size INTEGER NOT NULL CHECK (file_size >= 0),
    source_created_at TEXT,
    source_modified_at TEXT,
    operating_system TEXT,
    operating_system_version TEXT,
    architecture TEXT,
    acquisition_tool TEXT,
    acquisition_tool_version TEXT,
    acquisition_timestamp TEXT,
    acquisition_notes TEXT,
    is_read_only INTEGER NOT NULL DEFAULT 1 CHECK (is_read_only IN (0, 1)),
    added_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
);

-- ============================================================
-- Evidence hash records
-- ============================================================

CREATE TABLE IF NOT EXISTS evidence_hashes (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    analysis_run_id TEXT,
    algorithm TEXT NOT NULL DEFAULT 'SHA-256',
    hash_value TEXT NOT NULL,
    hash_stage TEXT NOT NULL CHECK (
        hash_stage IN (
            'acquisition',
            'pre_analysis',
            'post_analysis',
            'verification',
            'export'
        )
    ),
    file_size INTEGER NOT NULL CHECK (file_size >= 0),
    duration_seconds REAL CHECK (duration_seconds >= 0),
    calculated_at TEXT NOT NULL,
    verified INTEGER CHECK (verified IN (0, 1)),
    FOREIGN KEY (evidence_id) REFERENCES evidence_files (id) ON DELETE CASCADE
);

-- ============================================================
-- Chain-of-custody records
-- ============================================================

CREATE TABLE IF NOT EXISTS custody_events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    description TEXT NOT NULL,
    location TEXT,
    event_timestamp TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence_files (id) ON DELETE SET NULL
);

-- ============================================================
-- Analysis runs
-- ============================================================

CREATE TABLE IF NOT EXISTS analysis_runs (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    run_number INTEGER NOT NULL CHECK (run_number > 0),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN (
            'pending',
            'hashing',
            'running',
            'completed',
            'partial',
            'failed',
            'cancelled'
        )
    ),
    started_at TEXT,
    completed_at TEXT,
    application_version TEXT NOT NULL,
    python_version TEXT,
    volatility_version TEXT,
    yara_version TEXT,
    rule_set_version TEXT,
    worker_protocol_version TEXT,
    operating_system TEXT,
    hostname TEXT,
    configuration_json TEXT NOT NULL DEFAULT '{}',
    selected_plugins_json TEXT NOT NULL DEFAULT '[]',
    total_plugins INTEGER NOT NULL DEFAULT 0 CHECK (total_plugins >= 0),
    completed_plugins INTEGER NOT NULL DEFAULT 0 CHECK (completed_plugins >= 0),
    failed_plugins INTEGER NOT NULL DEFAULT 0 CHECK (failed_plugins >= 0),
    warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
    artifact_count INTEGER NOT NULL DEFAULT 0 CHECK (artifact_count >= 0),
    finding_count INTEGER NOT NULL DEFAULT 0 CHECK (finding_count >= 0),
    analysis_duration_seconds REAL CHECK (
        analysis_duration_seconds >= 0
    ),
    peak_memory_bytes INTEGER CHECK (peak_memory_bytes >= 0),
    cancellation_reason TEXT,
    failure_message TEXT,
    UNIQUE (case_id, run_number),
    FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence_files (id) ON DELETE RESTRICT
);

-- Add delayed reference after analysis_runs exists.
-- SQLite allows the column without declaring the FK earlier,
-- but integrity is enforced through application validation.

-- ============================================================
-- Plugin execution records
-- ============================================================

CREATE TABLE IF NOT EXISTS plugin_runs (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_name TEXT NOT NULL,
    plugin_category TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN (
            'pending',
            'running',
            'completed',
            'partial',
            'failed',
            'cancelled',
            'skipped',
            'timed_out'
        )
    ),
    command_arguments_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT,
    completed_at TEXT,
    duration_seconds REAL CHECK (duration_seconds >= 0),
    exit_code INTEGER,
    row_count INTEGER NOT NULL DEFAULT 0 CHECK (row_count >= 0),
    raw_output_path TEXT,
    stderr_output_path TEXT,
    raw_output_hash TEXT,
    stderr_output_hash TEXT,
    warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
    error_message TEXT,
    parser_version TEXT,
    parsing_status TEXT CHECK (
        parsing_status IS NULL
        OR parsing_status IN (
            'not_started',
            'running',
            'completed',
            'partial',
            'failed'
        )
    ),
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE
);

-- ============================================================
-- Processes
-- ============================================================

CREATE TABLE IF NOT EXISTS processes (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT,
    pid INTEGER NOT NULL CHECK (pid >= 0),
    ppid INTEGER CHECK (ppid >= 0),
    process_name TEXT NOT NULL,
    command_line TEXT,
    offset_virtual TEXT,
    offset_physical TEXT,
    created_at TEXT,
    exited_at TEXT,
    session_id INTEGER,
    wow64 INTEGER CHECK (wow64 IN (0, 1)),
    is_active INTEGER CHECK (is_active IN (0, 1)),
    is_hidden INTEGER CHECK (is_hidden IN (0, 1)),
    risk_score REAL NOT NULL DEFAULT 0 CHECK (risk_score >= 0),
    risk_level TEXT NOT NULL DEFAULT 'informational' CHECK (
        risk_level IN (
            'informational',
            'low',
            'medium',
            'high',
            'critical'
        )
    ),
    confidence_level TEXT CHECK (
        confidence_level IS NULL
        OR confidence_level IN ('low', 'medium', 'high')
    ),
    original_data_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_run_id) REFERENCES plugin_runs (id) ON DELETE SET NULL
);

-- ============================================================
-- Threads
-- ============================================================

CREATE TABLE IF NOT EXISTS threads (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT,
    process_id TEXT,
    pid INTEGER NOT NULL CHECK (pid >= 0),
    tid INTEGER NOT NULL CHECK (tid >= 0),
    start_address TEXT,
    win32_start_address TEXT,
    state TEXT,
    wait_reason TEXT,
    created_at TEXT,
    exited_at TEXT,
    starts_in_private_memory INTEGER CHECK (
        starts_in_private_memory IN (0, 1)
    ),
    starts_in_executable_memory INTEGER CHECK (
        starts_in_executable_memory IN (0, 1)
    ),
    original_data_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_run_id) REFERENCES plugin_runs (id) ON DELETE SET NULL,
    FOREIGN KEY (process_id) REFERENCES processes (id) ON DELETE SET NULL
);

-- ============================================================
-- Memory regions
-- ============================================================

CREATE TABLE IF NOT EXISTS memory_regions (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT,
    process_id TEXT,
    pid INTEGER NOT NULL CHECK (pid >= 0),
    start_address TEXT NOT NULL,
    end_address TEXT NOT NULL,
    region_size INTEGER CHECK (region_size >= 0),
    protection TEXT,
    tag TEXT,
    is_private INTEGER CHECK (is_private IN (0, 1)),
    is_executable INTEGER CHECK (is_executable IN (0, 1)),
    is_writable INTEGER CHECK (is_writable IN (0, 1)),
    is_readable INTEGER CHECK (is_readable IN (0, 1)),
    mapped_file TEXT,
    commit_charge INTEGER,
    hexdump_preview TEXT,
    disassembly_preview TEXT,
    original_data_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_run_id) REFERENCES plugin_runs (id) ON DELETE SET NULL,
    FOREIGN KEY (process_id) REFERENCES processes (id) ON DELETE SET NULL
);

-- ============================================================
-- Modules and DLLs
-- ============================================================

CREATE TABLE IF NOT EXISTS modules (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT,
    process_id TEXT,
    pid INTEGER CHECK (pid >= 0),
    module_name TEXT,
    module_path TEXT,
    base_address TEXT,
    image_size INTEGER CHECK (image_size >= 0),
    load_time TEXT,
    is_kernel_module INTEGER NOT NULL DEFAULT 0 CHECK (is_kernel_module IN (0, 1)),
    is_path_suspicious INTEGER CHECK (is_path_suspicious IN (0, 1)),
    original_data_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_run_id) REFERENCES plugin_runs (id) ON DELETE SET NULL,
    FOREIGN KEY (process_id) REFERENCES processes (id) ON DELETE SET NULL
);

-- ============================================================
-- Network connections
-- ============================================================

CREATE TABLE IF NOT EXISTS network_connections (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT,
    process_id TEXT,
    pid INTEGER CHECK (pid >= 0),
    process_name TEXT,
    protocol TEXT,
    local_address TEXT,
    local_port INTEGER CHECK (
        local_port IS NULL
        OR local_port BETWEEN 0 AND 65535
    ),
    remote_address TEXT,
    remote_port INTEGER CHECK (
        remote_port IS NULL
        OR remote_port BETWEEN 0 AND 65535
    ),
    connection_state TEXT,
    created_at TEXT,
    is_external INTEGER CHECK (is_external IN (0, 1)),
    original_data_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_run_id) REFERENCES plugin_runs (id) ON DELETE SET NULL,
    FOREIGN KEY (process_id) REFERENCES processes (id) ON DELETE SET NULL
);

-- ============================================================
-- YARA/signature matches
-- ============================================================

CREATE TABLE IF NOT EXISTS signature_matches (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT,
    process_id TEXT,
    memory_region_id TEXT,
    pid INTEGER CHECK (pid >= 0),
    rule_name TEXT NOT NULL,
    namespace TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    match_address TEXT,
    matched_string_identifier TEXT,
    matched_data_preview TEXT,
    rule_file_path TEXT,
    rule_file_hash TEXT,
    original_data_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_run_id) REFERENCES plugin_runs (id) ON DELETE SET NULL,
    FOREIGN KEY (process_id) REFERENCES processes (id) ON DELETE SET NULL,
    FOREIGN KEY (memory_region_id) REFERENCES memory_regions (id) ON DELETE SET NULL
);

-- ============================================================
-- Generic artifacts
-- Used for future artifact types not yet represented by
-- dedicated tables.
-- ============================================================

CREATE TABLE IF NOT EXISTS generic_artifacts (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT,
    artifact_type TEXT NOT NULL,
    pid INTEGER CHECK (pid >= 0),
    display_name TEXT,
    normalized_data_json TEXT NOT NULL DEFAULT '{}',
    original_data_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_run_id) REFERENCES plugin_runs (id) ON DELETE SET NULL
);

-- ============================================================
-- Evidence relationships
-- ============================================================

CREATE TABLE IF NOT EXISTS evidence_relationships (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    source_artifact_id TEXT NOT NULL,
    source_artifact_type TEXT NOT NULL,
    target_artifact_id TEXT NOT NULL,
    target_artifact_type TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    relationship_origin TEXT NOT NULL CHECK (
        relationship_origin IN (
            'observed',
            'derived',
            'inferred',
            'analyst_added'
        )
    ),
    confidence REAL CHECK (
        confidence IS NULL
        OR confidence BETWEEN 0 AND 1
    ),
    description TEXT,
    supporting_rule_id TEXT,
    provenance_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE
);

-- ============================================================
-- Rule definitions snapshot
-- Stores the exact rules used for an analysis run.
-- ============================================================

CREATE TABLE IF NOT EXISTS rule_definitions (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    description TEXT,
    rule_version TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    severity TEXT CHECK (
        severity IS NULL
        OR severity IN (
            'informational',
            'low',
            'medium',
            'high',
            'critical'
        )
    ),
    score REAL NOT NULL DEFAULT 0,
    configuration_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (analysis_run_id, rule_id),
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE
);

-- ============================================================
-- Findings
-- ============================================================

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    process_id TEXT,
    finding_code TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (
        severity IN (
            'informational',
            'low',
            'medium',
            'high',
            'critical'
        )
    ),
    risk_score REAL NOT NULL DEFAULT 0 CHECK (risk_score >= 0),
    confidence TEXT NOT NULL DEFAULT 'medium' CHECK (
        confidence IN ('low', 'medium', 'high')
    ),
    completeness TEXT NOT NULL DEFAULT 'complete' CHECK (
        completeness IN (
            'complete',
            'partial',
            'inconclusive'
        )
    ),
    status TEXT NOT NULL DEFAULT 'open' CHECK (
        status IN (
            'open',
            'reviewed',
            'accepted',
            'dismissed',
            'false_positive'
        )
    ),
    observed_evidence TEXT,
    inferred_explanation TEXT,
    benign_explanations TEXT,
    counter_evidence TEXT,
    limitations TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (process_id) REFERENCES processes (id) ON DELETE SET NULL
);

-- ============================================================
-- Rule contributions to findings
-- ============================================================

CREATE TABLE IF NOT EXISTS rule_contributions (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    rule_definition_id TEXT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    score_contribution REAL NOT NULL DEFAULT 0,
    confidence REAL CHECK (
        confidence IS NULL
        OR confidence BETWEEN 0 AND 1
    ),
    explanation TEXT NOT NULL,
    supporting_artifact_ids_json TEXT NOT NULL DEFAULT '[]',
    counter_evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE,
    FOREIGN KEY (rule_definition_id) REFERENCES rule_definitions (id) ON DELETE SET NULL
);

-- ============================================================
-- Finding-to-artifact links
-- ============================================================

CREATE TABLE IF NOT EXISTS finding_artifacts (
    finding_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    evidence_role TEXT NOT NULL CHECK (
        evidence_role IN (
            'supporting',
            'contradicting',
            'contextual',
            'affected'
        )
    ),
    description TEXT,
    PRIMARY KEY (
        finding_id,
        artifact_id,
        artifact_type,
        evidence_role
    ),
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

-- ============================================================
-- Analysis warnings and errors
-- ============================================================

CREATE TABLE IF NOT EXISTS analysis_messages (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT,
    level TEXT NOT NULL CHECK (
        level IN (
            'debug',
            'info',
            'warning',
            'error',
            'critical'
        )
    ),
    code TEXT,
    category TEXT,
    message TEXT NOT NULL,
    technical_details TEXT,
    is_user_visible INTEGER NOT NULL DEFAULT 1 CHECK (is_user_visible IN (0, 1)),
    created_at TEXT NOT NULL,
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_run_id) REFERENCES plugin_runs (id) ON DELETE CASCADE
);

-- ============================================================
-- Investigator notes
-- ============================================================

CREATE TABLE IF NOT EXISTS investigator_notes (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    analysis_run_id TEXT,
    finding_id TEXT,
    artifact_id TEXT,
    artifact_type TEXT,
    author TEXT NOT NULL,
    note_text TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_deleted INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),
    FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE,
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE SET NULL,
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE SET NULL
);

-- ============================================================
-- Note revision history
-- ============================================================

CREATE TABLE IF NOT EXISTS investigator_note_revisions (
    id TEXT PRIMARY KEY,
    note_id TEXT NOT NULL,
    previous_text TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    FOREIGN KEY (note_id) REFERENCES investigator_notes (id) ON DELETE CASCADE
);

-- ============================================================
-- Generated reports
-- ============================================================

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    report_type TEXT NOT NULL CHECK (
        report_type IN (
            'json',
            'html',
            'csv',
            'graphml',
            'redacted_html',
            'redacted_json'
        )
    ),
    report_path TEXT NOT NULL,
    report_hash TEXT,
    hash_algorithm TEXT DEFAULT 'SHA-256',
    template_version TEXT,
    redaction_applied INTEGER NOT NULL DEFAULT 0 CHECK (redaction_applied IN (0, 1)),
    redaction_configuration_json TEXT,
    generated_by TEXT,
    generated_at TEXT NOT NULL,
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE
);

-- ============================================================
-- File inventory
-- Tracks files produced during an analysis.
-- ============================================================

CREATE TABLE IF NOT EXISTS generated_files (
    id TEXT PRIMARY KEY,
    analysis_run_id TEXT NOT NULL,
    plugin_run_id TEXT,
    file_category TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    file_size INTEGER NOT NULL CHECK (file_size >= 0),
    hash_algorithm TEXT DEFAULT 'SHA-256',
    hash_value TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (
        analysis_run_id,
        relative_path
    ),
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE CASCADE,
    FOREIGN KEY (plugin_run_id) REFERENCES plugin_runs (id) ON DELETE SET NULL
);

-- ============================================================
-- Audit log
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    analysis_run_id TEXT,
    actor TEXT,
    event_type TEXT NOT NULL,
    event_description TEXT NOT NULL,
    object_type TEXT,
    object_id TEXT,
    event_data_json TEXT NOT NULL DEFAULT '{}',
    event_timestamp TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE,
    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (id) ON DELETE SET NULL
);

-- ============================================================
-- Application settings
-- ============================================================

CREATE TABLE IF NOT EXISTS application_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    value_type TEXT NOT NULL DEFAULT 'string' CHECK (
        value_type IN (
            'string',
            'integer',
            'float',
            'boolean',
            'json'
        )
    ),
    updated_at TEXT NOT NULL
);

-- ============================================================
-- Indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_evidence_files_case ON evidence_files (case_id);

CREATE INDEX IF NOT EXISTS idx_evidence_hashes_evidence ON evidence_hashes (evidence_id);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_case ON analysis_runs (case_id);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_evidence ON analysis_runs (evidence_id);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_status ON analysis_runs (status);

CREATE INDEX IF NOT EXISTS idx_plugin_runs_analysis ON plugin_runs (analysis_run_id);

CREATE INDEX IF NOT EXISTS idx_plugin_runs_name ON plugin_runs (plugin_name);

CREATE INDEX IF NOT EXISTS idx_plugin_runs_status ON plugin_runs (status);

CREATE INDEX IF NOT EXISTS idx_processes_analysis_pid ON processes (analysis_run_id, pid);

CREATE INDEX IF NOT EXISTS idx_processes_parent ON processes (analysis_run_id, ppid);

CREATE INDEX IF NOT EXISTS idx_processes_name ON processes (process_name);

CREATE INDEX IF NOT EXISTS idx_processes_risk ON processes (
    analysis_run_id,
    risk_score DESC
);

CREATE INDEX IF NOT EXISTS idx_threads_analysis_pid ON threads (analysis_run_id, pid);

CREATE INDEX IF NOT EXISTS idx_threads_tid ON threads (analysis_run_id, tid);

CREATE INDEX IF NOT EXISTS idx_memory_regions_analysis_pid ON memory_regions (analysis_run_id, pid);

CREATE INDEX IF NOT EXISTS idx_memory_regions_process ON memory_regions (process_id);

CREATE INDEX IF NOT EXISTS idx_modules_analysis_pid ON modules (analysis_run_id, pid);

CREATE INDEX IF NOT EXISTS idx_network_analysis_pid ON network_connections (analysis_run_id, pid);

CREATE INDEX IF NOT EXISTS idx_network_remote_address ON network_connections (remote_address);

CREATE INDEX IF NOT EXISTS idx_signature_matches_analysis ON signature_matches (analysis_run_id);

CREATE INDEX IF NOT EXISTS idx_signature_matches_rule ON signature_matches (rule_name);

CREATE INDEX IF NOT EXISTS idx_relationships_analysis ON evidence_relationships (analysis_run_id);

CREATE INDEX IF NOT EXISTS idx_relationships_source ON evidence_relationships (
    source_artifact_type,
    source_artifact_id
);

CREATE INDEX IF NOT EXISTS idx_relationships_target ON evidence_relationships (
    target_artifact_type,
    target_artifact_id
);

CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings (analysis_run_id);

CREATE INDEX IF NOT EXISTS idx_findings_process ON findings (process_id);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (analysis_run_id, severity);

CREATE INDEX IF NOT EXISTS idx_findings_score ON findings (
    analysis_run_id,
    risk_score DESC
);

CREATE INDEX IF NOT EXISTS idx_rule_contributions_finding ON rule_contributions (finding_id);

CREATE INDEX IF NOT EXISTS idx_messages_analysis ON analysis_messages (analysis_run_id);

CREATE INDEX IF NOT EXISTS idx_messages_level ON analysis_messages (level);

CREATE INDEX IF NOT EXISTS idx_notes_case ON investigator_notes (case_id);

CREATE INDEX IF NOT EXISTS idx_reports_analysis ON reports (analysis_run_id);

CREATE INDEX IF NOT EXISTS idx_audit_case_time ON audit_events (case_id, event_timestamp);

-- ============================================================
-- Views
-- ============================================================

CREATE VIEW IF NOT EXISTS process_summary AS
SELECT
    p.id AS process_id,
    p.analysis_run_id,
    p.pid,
    p.ppid,
    p.process_name,
    p.command_line,
    p.risk_score,
    p.risk_level,
    p.confidence_level,
    COUNT(DISTINCT mr.id) AS memory_region_count,
    COUNT(
        DISTINCT CASE
            WHEN mr.is_private = 1
            AND mr.is_executable = 1 THEN mr.id
        END
    ) AS private_executable_region_count,
    COUNT(DISTINCT nc.id) AS network_connection_count,
    COUNT(DISTINCT sm.id) AS yara_match_count,
    COUNT(DISTINCT f.id) AS finding_count
FROM
    processes p
    LEFT JOIN memory_regions mr ON mr.process_id = p.id
    LEFT JOIN network_connections nc ON nc.process_id = p.id
    LEFT JOIN signature_matches sm ON sm.process_id = p.id
    LEFT JOIN findings f ON f.process_id = p.id
GROUP BY
    p.id,
    p.analysis_run_id,
    p.pid,
    p.ppid,
    p.process_name,
    p.command_line,
    p.risk_score,
    p.risk_level,
    p.confidence_level;

CREATE VIEW IF NOT EXISTS plugin_execution_summary AS
SELECT
    analysis_run_id,
    COUNT(*) AS total_plugins,
    SUM(
        CASE
            WHEN status = 'completed' THEN 1
            ELSE 0
        END
    ) AS completed_plugins,
    SUM(
        CASE
            WHEN status = 'failed' THEN 1
            ELSE 0
        END
    ) AS failed_plugins,
    SUM(
        CASE
            WHEN status = 'partial' THEN 1
            ELSE 0
        END
    ) AS partial_plugins,
    SUM(
        CASE
            WHEN status = 'timed_out' THEN 1
            ELSE 0
        END
    ) AS timed_out_plugins,
    SUM(
        CASE
            WHEN status = 'cancelled' THEN 1
            ELSE 0
        END
    ) AS cancelled_plugins
FROM plugin_runs
GROUP BY
    analysis_run_id;

CREATE VIEW IF NOT EXISTS finding_summary AS
SELECT
    f.id AS finding_id,
    f.analysis_run_id,
    f.finding_code,
    f.title,
    f.severity,
    f.risk_score,
    f.confidence,
    f.completeness,
    f.status,
    p.pid,
    p.process_name,
    COUNT(rc.id) AS triggered_rule_count
FROM
    findings f
    LEFT JOIN processes p ON p.id = f.process_id
    LEFT JOIN rule_contributions rc ON rc.finding_id = f.id
GROUP BY
    f.id,
    f.analysis_run_id,
    f.finding_code,
    f.title,
    f.severity,
    f.risk_score,
    f.confidence,
    f.completeness,
    f.status,
    p.pid,
    p.process_name;

COMMIT;