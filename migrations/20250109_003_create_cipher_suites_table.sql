-- Create cipher_suites table (detected cipher suites)
-- Supports both PostgreSQL and SQLite

CREATE TABLE IF NOT EXISTS cipher_suites (
    cipher_id INTEGER  PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    protocol_name VARCHAR(20) NOT NULL,
    cipher_name VARCHAR(255) NOT NULL,
    key_exchange VARCHAR(50),
    authentication VARCHAR(50),
    encryption VARCHAR(50),
    mac VARCHAR(50),
    bits INTEGER,
    forward_secrecy BOOLEAN NOT NULL DEFAULT FALSE,
    strength VARCHAR(20) NOT NULL  -- 'weak', 'medium', 'strong'
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_ciphers_scan ON cipher_suites(scan_id);
CREATE INDEX IF NOT EXISTS idx_ciphers_strength ON cipher_suites(strength);
