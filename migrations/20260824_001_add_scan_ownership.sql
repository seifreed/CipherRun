-- Preserve the API principal and tenant that created each historical scan.
-- Nullable columns keep CLI and pre-existing rows compatible.
ALTER TABLE scans ADD COLUMN principal_id VARCHAR(255);
ALTER TABLE scans ADD COLUMN tenant_id VARCHAR(255);
ALTER TABLE scans ADD COLUMN created_by_key_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(principal_id, tenant_id, scan_timestamp DESC);
