# CipherRun Database Backend

This document describes the database persistence layer for CipherRun, a TLS/SSL security scanner.

## Overview

CipherRun supports storing scan results in a relational database for:
- **Historical tracking**: Monitor security posture changes over time
- **Trend analysis**: Identify improvements or regressions
- **Compliance reporting**: Generate audit trails
- **Comparison**: Compare current vs. historical scans

## Supported Databases

- **PostgreSQL** (recommended for production)
- **SQLite** (suitable for development and single-user scenarios)

Both backends use the same API and schema, allowing seamless switching.

## Quick Start

### 1. Generate Example Configuration

```bash
cipherrun --db-config-example database.toml
```

### 2. Configure Database

Edit `database.toml`:

**For PostgreSQL:**
```toml
[database]
type = "postgres"
host = "localhost"
port = 5432
database = "cipherrun"
username = "cipherrun_user"
password = "secure_password"
max_connections = 10

[retention]
max_age_days = 365
```

**For SQLite:**
```toml
[database]
type = "sqlite"
path = "./cipherrun.db"

[retention]
max_age_days = 365
```

### 3. Initialize Database

```bash
cipherrun --db-config database.toml --db-init
```

This creates all tables and runs migrations automatically.

### 4. Scan and Store Results

```bash
cipherrun example.com --all --db-config database.toml --store
```

## Database Schema

### Tables

#### `scans` (Parent Record)
Stores metadata for each scan:
- `scan_id` (PRIMARY KEY)
- `target_hostname`
- `target_port`
- `scan_timestamp`
- `overall_grade` (SSL Labs grade)
- `overall_score` (0-100)
- `scan_duration_ms`
- `scanner_version`

**Indexes:**
- Composite: `(target_hostname, target_port, scan_timestamp DESC)`
- Timestamp: `(scan_timestamp DESC)`

#### `protocols`
Detected TLS/SSL protocols:
- `protocol_id` (PRIMARY KEY)
- `scan_id` (FOREIGN KEY → scans)
- `protocol_name` (e.g., "TLS 1.3")
- `enabled` (boolean)
- `preferred` (boolean)

#### `cipher_suites`
Supported cipher suites:
- `cipher_id` (PRIMARY KEY)
- `scan_id` (FOREIGN KEY → scans)
- `protocol_name`
- `cipher_name`
- `key_exchange`, `authentication`, `encryption`, `mac`
- `bits` (key size)
- `forward_secrecy` (boolean)
- `strength` ("weak", "medium", "strong")

**Indexes:**
- `(scan_id)`
- `(strength)`

#### `certificates`
X.509 certificates (deduplicated by SHA256 fingerprint):
- `cert_id` (PRIMARY KEY)
- `fingerprint_sha256` (UNIQUE)
- `subject`, `issuer`
- `serial_number`
- `not_before`, `not_after` (validity period)
- `signature_algorithm`, `public_key_algorithm`
- `public_key_size`
- `san_domains` (JSON array)
- `is_ca` (boolean)
- `key_usage`, `extended_key_usage` (JSON arrays)
- `der_bytes` (full DER encoding)

**Deduplication:** Certificates are stored once and linked to multiple scans via junction table.

#### `scan_certificates` (Junction Table)
Links certificates to scans:
- `id` (PRIMARY KEY)
- `scan_id` (FOREIGN KEY → scans)
- `cert_id` (FOREIGN KEY → certificates)
- `chain_position` (0 = leaf, 1 = intermediate, etc.)

#### `vulnerabilities`
Detected vulnerabilities:
- `vuln_id` (PRIMARY KEY)
- `scan_id` (FOREIGN KEY → scans)
- `vulnerability_type` (e.g., "Heartbleed")
- `severity` ("critical", "high", "medium", "low", "info")
- `description`
- `cve_id`
- `affected_component`

**Indexes:**
- `(scan_id)`
- `(severity)`

#### `ratings`
SSL Labs-style rating components:
- `rating_id` (PRIMARY KEY)
- `scan_id` (FOREIGN KEY → scans)
- `category` ("protocol", "key_exchange", "cipher", "certificate")
- `score` (0-100)
- `grade` (e.g., "A+")
- `rationale` (explanation)

## CLI Usage

### Store Scan Results

```bash
# Run scan and store in database
cipherrun example.com --all --db-config database.toml --store
```

### Query Scan History

```bash
# Show last 10 scans for example.com:443
cipherrun --db-config database.toml --history example.com:443

# Show last 20 scans
cipherrun --db-config database.toml --history example.com:443 --history-limit 20
```

### Cleanup Old Scans

```bash
# Delete scans older than 90 days
cipherrun --db-config database.toml --cleanup-days 90
```

### Database Initialization

```bash
# Initialize database (create tables, run migrations)
cipherrun --db-config database.toml --db-init
```

## PostgreSQL Setup

### 1. Install PostgreSQL

```bash
# macOS
brew install postgresql

# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# RHEL/CentOS
sudo yum install postgresql-server postgresql-contrib
```

### 2. Create Database and User

```sql
-- Connect as postgres superuser
sudo -u postgres psql

-- Create user
CREATE USER cipherrun_user WITH PASSWORD 'secure_password';

-- Create database
CREATE DATABASE cipherrun OWNER cipherrun_user;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cipherrun TO cipherrun_user;
```

### 3. Configure Connection

Edit `database.toml`:
```toml
[database]
type = "postgres"
host = "localhost"
port = 5432
database = "cipherrun"
username = "cipherrun_user"
password = "secure_password"
```

### 4. Initialize Schema

```bash
cipherrun --db-config database.toml --db-init
```

## SQLite Setup

### 1. Configuration

SQLite requires no server setup. Just specify the database file path:

```toml
[database]
type = "sqlite"
path = "./cipherrun.db"
```

### 2. Initialize Database

```bash
cipherrun --db-config database.toml --db-init
```

The database file will be created automatically.

## Migration System

CipherRun uses sqlx migrations located in `migrations/`:

```
migrations/
├── 20250109_001_create_scans_table.sql
├── 20250109_002_create_protocols_table.sql
├── 20250109_003_create_cipher_suites_table.sql
├── 20250109_004_create_certificates_table.sql
├── 20250109_005_create_scan_certificates_table.sql
├── 20250109_006_create_vulnerabilities_table.sql
└── 20250109_007_create_ratings_table.sql
```

Migrations run automatically when you use `--db-init`.

## Query Examples

### PostgreSQL

```sql
-- Get latest scan for a hostname
SELECT * FROM scans
WHERE target_hostname = 'example.com'
ORDER BY scan_timestamp DESC
LIMIT 1;

-- Count vulnerabilities by severity
SELECT severity, COUNT(*) as count
FROM vulnerabilities v
JOIN scans s ON v.scan_id = s.scan_id
WHERE s.target_hostname = 'example.com'
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;

-- Track grade changes over time
SELECT scan_timestamp, overall_grade, overall_score
FROM scans
WHERE target_hostname = 'example.com' AND target_port = 443
ORDER BY scan_timestamp DESC
LIMIT 10;

-- Find weak ciphers
SELECT DISTINCT c.cipher_name, c.strength
FROM cipher_suites c
JOIN scans s ON c.scan_id = s.scan_id
WHERE s.target_hostname = 'example.com'
  AND c.strength IN ('weak', 'low')
ORDER BY c.cipher_name;

-- Certificate expiration tracking
SELECT s.target_hostname, c.subject, c.not_after
FROM certificates c
JOIN scan_certificates sc ON c.cert_id = sc.cert_id
JOIN scans s ON sc.scan_id = s.scan_id
WHERE sc.chain_position = 0  -- Leaf certificate
  AND c.not_after < NOW() + INTERVAL '30 days'
ORDER BY c.not_after;
```

### SQLite

```sql
-- Same queries work with SQLite, with minor syntax differences:

-- Certificate expiration (SQLite syntax)
SELECT s.target_hostname, c.subject, c.not_after
FROM certificates c
JOIN scan_certificates sc ON c.cert_id = sc.cert_id
JOIN scans s ON sc.scan_id = s.scan_id
WHERE sc.chain_position = 0
  AND c.not_after < datetime('now', '+30 days')
ORDER BY c.not_after;
```

## Performance Considerations

### Indexes

All tables have appropriate indexes for common queries:
- Scans: Composite index on `(hostname, port, timestamp)`
- Protocols, Ciphers, Vulnerabilities, Ratings: Index on `scan_id`
- Certificates: Unique index on `fingerprint_sha256`

### Connection Pooling

- **PostgreSQL**: Configurable connection pool (default: 10)
- **SQLite**: Single connection (SQLite is single-writer)

### Cleanup Strategy

Use the retention policy to automatically delete old scans:

```toml
[retention]
max_age_days = 365  # Keep 1 year of history
```

Manual cleanup:
```bash
cipherrun --db-config database.toml --cleanup-days 90
```

## Security Best Practices

1. **PostgreSQL:**
   - Use strong passwords
   - Enable SSL/TLS for remote connections
   - Configure `pg_hba.conf` for IP restrictions
   - Use separate database user with minimal privileges

2. **SQLite:**
   - Protect database file with filesystem permissions
   - Consider encrypting the database file at rest
   - Use SQLite only for local/trusted environments

3. **Connection Strings:**
   - Never commit `database.toml` with credentials to version control
   - Use environment variables for sensitive values
   - Rotate database passwords regularly

## Troubleshooting

### Migration Failures

If migrations fail, check:
1. Database connectivity
2. User permissions (CREATE TABLE, CREATE INDEX)
3. Existing schema conflicts

Reset migrations (CAUTION: Deletes all data):
```sql
-- PostgreSQL
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;

-- SQLite
rm cipherrun.db
```

### Connection Issues

```bash
# Test PostgreSQL connection
psql -h localhost -U cipherrun_user -d cipherrun

# Check SQLite database
sqlite3 cipherrun.db ".tables"
```

### Performance Issues

For large datasets:
1. Increase PostgreSQL `shared_buffers` and `work_mem`
2. Run `VACUUM ANALYZE` periodically
3. Consider partitioning `scans` table by date
4. Add custom indexes for specific queries

## API Usage (Rust)

```rust
use cipherrun::db::{CipherRunDatabase, DatabaseConfig};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load from config file
    let db = CipherRunDatabase::from_config_file("database.toml").await?;

    // Or create programmatically
    let config = DatabaseConfig::sqlite(PathBuf::from("test.db"));
    let db = CipherRunDatabase::new(&config).await?;

    // Store scan results
    let scan_id = db.store_scan(&scan_results).await?;

    // Query history
    let history = db.get_scan_history("example.com", 443, 10).await?;

    // Cleanup
    let deleted = db.cleanup_old_scans(365).await?;

    db.close().await;
    Ok(())
}
```

## License

This database module is part of CipherRun and is licensed under GPL-3.0.

## Support

For issues or questions:
- GitHub: https://github.com/seifreed/cipherrun
- Author: Marc Rivero (@seifreed)
