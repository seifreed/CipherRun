-- Remove API ownership metadata from historical scans.
DROP INDEX IF EXISTS idx_scans_owner;
ALTER TABLE scans DROP COLUMN principal_id;
ALTER TABLE scans DROP COLUMN tenant_id;
ALTER TABLE scans DROP COLUMN created_by_key_id;
