ALTER TABLE evidence ADD COLUMN path_base TEXT NOT NULL DEFAULT 'original'
    CHECK (path_base IN ('original', 'case'));
