-- Create scans table (parent record for all scan data)
-- Supports both PostgreSQL and SQLite

CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_hostname VARCHAR(255) NOT NULL,
    target_port INTEGER NOT NULL DEFAULT 443,
    scan_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    overall_grade VARCHAR(5),
    overall_score INTEGER,
    scan_duration_ms INTEGER,
    scanner_version VARCHAR(50)
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_scans_composite ON scans(target_hostname, target_port, scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(scan_timestamp DESC);
