CREATE TABLE cases (
    id TEXT PRIMARY KEY,
    case_number TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    CHECK (status IN ('open', 'closed', 'archived'))
);