-- Create vulnerabilities table (detected vulnerabilities)
-- Supports both PostgreSQL and SQLite

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id INTEGER  PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    vulnerability_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- 'critical', 'high', 'medium', 'low', 'info'
    description TEXT,
    cve_id VARCHAR(50),
    affected_component VARCHAR(100)
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_vuln_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
