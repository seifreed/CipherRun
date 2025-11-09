-- Create ratings table (SSL Labs-style rating components)
-- Supports both PostgreSQL and SQLite

CREATE TABLE IF NOT EXISTS ratings (
    rating_id INTEGER  PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL,  -- 'protocol', 'key_exchange', 'cipher', 'certificate'
    score INTEGER NOT NULL,  -- 0-100
    grade VARCHAR(5),
    rationale TEXT
);

-- Index for fast lookup by scan
CREATE INDEX IF NOT EXISTS idx_rating_scan ON ratings(scan_id);
