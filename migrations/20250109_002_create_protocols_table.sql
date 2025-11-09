-- Create protocols table (detected TLS/SSL protocols)
-- Supports both PostgreSQL and SQLite

CREATE TABLE IF NOT EXISTS protocols (
    protocol_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    protocol_name VARCHAR(20) NOT NULL,  -- 'TLS 1.2', 'TLS 1.3', etc.
    enabled BOOLEAN NOT NULL,
    preferred BOOLEAN NOT NULL DEFAULT FALSE
);

-- Index for fast lookup by scan
CREATE INDEX IF NOT EXISTS idx_protocols_scan ON protocols(scan_id);
