-- Remove serialized revocation payload from scans
-- Supports both PostgreSQL and SQLite

ALTER TABLE scans DROP COLUMN revocation_json;
