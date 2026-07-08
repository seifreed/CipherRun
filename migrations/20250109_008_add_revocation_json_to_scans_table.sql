-- Add serialized revocation payload to scans
-- Supports both PostgreSQL and SQLite

ALTER TABLE scans ADD COLUMN revocation_json TEXT;
