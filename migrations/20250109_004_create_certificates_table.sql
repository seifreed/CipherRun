-- Create certificates table (deduplicated by fingerprint)
-- Supports both PostgreSQL and SQLite

CREATE TABLE IF NOT EXISTS certificates (
    cert_id INTEGER  PRIMARY KEY AUTOINCREMENT,
    fingerprint_sha256 VARCHAR(95) NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    serial_number VARCHAR(255),
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    signature_algorithm VARCHAR(100),
    public_key_algorithm VARCHAR(100),
    public_key_size INTEGER,
    san_domains TEXT,  -- JSON array for SQLite, ARRAY for PostgreSQL
    is_ca BOOLEAN NOT NULL DEFAULT FALSE,
    key_usage TEXT,  -- JSON array for SQLite, ARRAY for PostgreSQL
    extended_key_usage TEXT,  -- JSON array for SQLite, ARRAY for PostgreSQL
    der_bytes BLOB,  -- Full DER encoding
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_cert_fingerprint ON certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_expiry ON certificates(not_after);
