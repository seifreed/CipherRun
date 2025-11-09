-- Create scan_certificates table (certificate chain junction)
-- Supports both PostgreSQL and SQLite

CREATE TABLE IF NOT EXISTS scan_certificates (
    id INTEGER  PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    cert_id INTEGER NOT NULL REFERENCES certificates(cert_id) ON DELETE CASCADE,
    chain_position INTEGER NOT NULL  -- 0 = leaf, 1 = intermediate, etc.
);

-- Index for fast lookup by scan and position
CREATE INDEX IF NOT EXISTS idx_scan_certs ON scan_certificates(scan_id, chain_position);
