use crate::application::{
    CertificateInventoryPage, CertificateInventoryPort, CertificateInventoryQuery,
    CertificateInventoryRecord, CertificateInventorySort,
};
use crate::db::DatabasePool;
use chrono::Utc;
use sqlx::{Row, postgres::PgRow, sqlite::SqliteRow};

impl CertificateInventorySort {
    fn as_order_by(&self) -> &'static str {
        match self {
            Self::ExpiryAsc => "c.not_after ASC",
            Self::ExpiryDesc => "c.not_after DESC",
            Self::IssuedAsc => "c.not_before ASC",
            Self::IssuedDesc => "c.not_before DESC",
        }
    }
}

pub struct CertificateInventoryService<'a> {
    pool: &'a DatabasePool,
}

impl<'a> CertificateInventoryService<'a> {
    pub fn new(pool: &'a DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl<'a> CertificateInventoryPort for CertificateInventoryService<'a> {
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "certificate_inventory.list"
        )
    )]
    async fn list_certificates(
        &self,
        query: &CertificateInventoryQuery,
    ) -> crate::Result<CertificateInventoryPage> {
        list_certificates(self.pool, query).await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "certificate_inventory.get"
        )
    )]
    async fn get_certificate(
        &self,
        fingerprint: &str,
    ) -> crate::Result<Option<CertificateInventoryRecord>> {
        get_certificate(self.pool, fingerprint).await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "certificate_inventory.get_for_owner"
        )
    )]
    async fn get_certificate_for_owner(
        &self,
        fingerprint: &str,
        principal_id: Option<&str>,
        tenant_id: Option<&str>,
    ) -> crate::Result<Option<CertificateInventoryRecord>> {
        get_certificate_for_owner(self.pool, fingerprint, principal_id, tenant_id).await
    }
}

struct CertificateListQuery {
    where_clause: String,
    params: Vec<String>,
    order_by: &'static str,
}

#[derive(Clone, Copy)]
enum SqlDialect {
    Postgres,
    Sqlite,
}

impl SqlDialect {
    fn placeholder(self, position: usize) -> String {
        match self {
            Self::Postgres => format!("${}", position),
            Self::Sqlite => "?".to_string(),
        }
    }
}

pub async fn list_certificates(
    pool: &DatabasePool,
    query: &CertificateInventoryQuery,
) -> crate::Result<CertificateInventoryPage> {
    let (total, certificates) = match pool {
        DatabasePool::Postgres(pool) => {
            let query_parts =
                build_certificate_list_query_for_dialect(query, SqlDialect::Postgres)?;
            (
                fetch_certificate_count_postgres(pool, &query_parts).await?,
                fetch_certificate_list_postgres(pool, query, &query_parts).await?,
            )
        }
        DatabasePool::Sqlite(pool) => {
            let query_parts = build_certificate_list_query(query)?;
            (
                fetch_certificate_count_sqlite(pool, &query_parts).await?,
                fetch_certificate_list_sqlite(pool, query, &query_parts).await?,
            )
        }
    };

    Ok(CertificateInventoryPage {
        total,
        certificates,
    })
}

pub async fn get_certificate(
    pool: &DatabasePool,
    fingerprint: &str,
) -> crate::Result<Option<CertificateInventoryRecord>> {
    match pool {
        DatabasePool::Postgres(pool) => {
            fetch_certificate_detail_postgres(pool, fingerprint, None, None).await
        }
        DatabasePool::Sqlite(pool) => {
            fetch_certificate_detail_sqlite(pool, fingerprint, None, None).await
        }
    }
}

pub async fn get_certificate_for_owner(
    pool: &DatabasePool,
    fingerprint: &str,
    principal_id: Option<&str>,
    tenant_id: Option<&str>,
) -> crate::Result<Option<CertificateInventoryRecord>> {
    match pool {
        DatabasePool::Postgres(pool) => {
            fetch_certificate_detail_postgres(pool, fingerprint, principal_id, tenant_id).await
        }
        DatabasePool::Sqlite(pool) => {
            fetch_certificate_detail_sqlite(pool, fingerprint, principal_id, tenant_id).await
        }
    }
}

fn build_certificate_list_query(
    query: &CertificateInventoryQuery,
) -> crate::Result<CertificateListQuery> {
    build_certificate_list_query_for_dialect(query, SqlDialect::Sqlite)
}

fn build_certificate_list_query_for_dialect(
    query: &CertificateInventoryQuery,
    dialect: SqlDialect,
) -> crate::Result<CertificateListQuery> {
    let mut where_clauses = Vec::new();
    let mut params = Vec::new();

    if let Some(ref hostname) = query.hostname {
        let placeholder = dialect.placeholder(params.len() + 1);
        where_clauses.push(format!(
            "EXISTS (SELECT 1 FROM scan_certificates sc JOIN scans s ON sc.scan_id = s.scan_id WHERE sc.cert_id = c.cert_id AND LOWER(s.target_hostname) = {})",
            placeholder
        ));
        params.push(hostname.clone());
    }

    if let Some(ref principal_id) = query.principal_id {
        let principal_placeholder = dialect.placeholder(params.len() + 1);
        params.push(principal_id.clone());
        let tenant_match = if let Some(tenant_id) = &query.tenant_id {
            let tenant_placeholder = dialect.placeholder(params.len() + 1);
            params.push(tenant_id.clone());
            match dialect {
                SqlDialect::Postgres => format!("s.tenant_id = {}", tenant_placeholder),
                SqlDialect::Sqlite => format!("s.tenant_id = {}", tenant_placeholder),
            }
        } else {
            "s.tenant_id IS NULL".to_string()
        };
        where_clauses.push(format!(
            "EXISTS (SELECT 1 FROM scan_certificates owner_sc JOIN scans s ON owner_sc.scan_id = s.scan_id WHERE owner_sc.cert_id = c.cert_id AND s.principal_id = {} AND {})",
            principal_placeholder, tenant_match
        ));
    }

    if let Some(days) = query.expiring_within_days {
        let duration = chrono::Duration::try_days(i64::from(days)).ok_or_else(|| {
            crate::TlsError::InvalidInput {
                message: format!("expiring_within_days value is too large: {days}"),
            }
        })?;
        let cutoff_date = Utc::now().checked_add_signed(duration).ok_or_else(|| {
            crate::TlsError::InvalidInput {
                message: format!("expiring_within_days value is too large: {days}"),
            }
        })?;
        let placeholder = dialect.placeholder(params.len() + 1);
        // `not_after` is stored as a native datetime whose textual encoding
        // differs from `to_rfc3339()` (separator/fractional digits). On SQLite,
        // whose typing is dynamic, a raw string `<=` is a lexical comparison
        // that mis-orders same-date values (the stored space separator sorts
        // before the bound 'T'), over-including certs that expire later on the
        // cutoff day. Normalize both sides as timestamps so the comparison is
        // chronological on both backends.
        let predicate = match dialect {
            SqlDialect::Postgres => format!("c.not_after <= {}::timestamptz", placeholder),
            SqlDialect::Sqlite => format!("datetime(c.not_after) <= datetime({})", placeholder),
        };
        where_clauses.push(predicate);
        params.push(cutoff_date.to_rfc3339());
    }

    let where_clause = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    Ok(CertificateListQuery {
        where_clause,
        params,
        order_by: query.sort.as_order_by(),
    })
}

fn normalize_fingerprint_lookup(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

async fn fetch_certificate_count_postgres(
    pool: &sqlx::PgPool,
    query_parts: &CertificateListQuery,
) -> crate::Result<usize> {
    let count_query = format!(
        "SELECT COUNT(*) as count FROM certificates c {}",
        query_parts.where_clause
    );
    let mut count_stmt = sqlx::query(&count_query);
    for param in &query_parts.params {
        count_stmt = count_stmt.bind(param);
    }

    let total: i64 = count_stmt
        .fetch_one(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to count certificates: {}", e))
        })?
        .get("count");
    non_negative_count(total, "certificate count")
}

async fn fetch_certificate_count_sqlite(
    pool: &sqlx::SqlitePool,
    query_parts: &CertificateListQuery,
) -> crate::Result<usize> {
    let count_query = format!(
        "SELECT COUNT(*) as count FROM certificates c {}",
        query_parts.where_clause
    );
    let mut count_stmt = sqlx::query(&count_query);
    for param in &query_parts.params {
        count_stmt = count_stmt.bind(param);
    }

    let total: i64 = count_stmt
        .fetch_one(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to count certificates: {}", e))
        })?
        .get("count");
    non_negative_count(total, "certificate count")
}

fn certificate_field_error(field: &str, error: impl std::fmt::Display) -> crate::TlsError {
    crate::TlsError::DatabaseError(format!("Invalid certificate field {}: {}", field, error))
}

fn non_negative_count(value: i64, field: &str) -> crate::Result<usize> {
    usize::try_from(value).map_err(|error| certificate_field_error(field, error))
}

fn usize_to_i64(value: usize, field: &str) -> crate::Result<i64> {
    i64::try_from(value).map_err(|error| certificate_field_error(field, error))
}

fn certificate_record_from_pg_row(row: PgRow) -> crate::Result<CertificateInventoryRecord> {
    let fingerprint = row
        .try_get("fingerprint_sha256")
        .map_err(|e| certificate_field_error("fingerprint_sha256", e))?;
    let subject = row
        .try_get("subject")
        .map_err(|e| certificate_field_error("subject", e))?;
    let issuer = row
        .try_get("issuer")
        .map_err(|e| certificate_field_error("issuer", e))?;
    let not_before = row
        .try_get("not_before")
        .map_err(|e| certificate_field_error("not_before", e))?;
    let not_after = row
        .try_get("not_after")
        .map_err(|e| certificate_field_error("not_after", e))?;
    let san_json = row
        .try_get("san_domains")
        .map_err(|e| certificate_field_error("san_domains", e))?;
    let hostnames: Option<Vec<String>> = row
        .try_get("hostnames")
        .map_err(|e| certificate_field_error("hostnames", e))?;

    Ok(CertificateInventoryRecord {
        fingerprint,
        subject,
        issuer,
        not_before,
        not_after,
        san_json,
        hostnames: hostnames.unwrap_or_default(),
    })
}

fn certificate_record_from_sqlite_row(row: SqliteRow) -> crate::Result<CertificateInventoryRecord> {
    let fingerprint = row
        .try_get("fingerprint_sha256")
        .map_err(|e| certificate_field_error("fingerprint_sha256", e))?;
    let subject = row
        .try_get("subject")
        .map_err(|e| certificate_field_error("subject", e))?;
    let issuer = row
        .try_get("issuer")
        .map_err(|e| certificate_field_error("issuer", e))?;
    let not_before = row
        .try_get("not_before")
        .map_err(|e| certificate_field_error("not_before", e))?;
    let not_after = row
        .try_get("not_after")
        .map_err(|e| certificate_field_error("not_after", e))?;
    let san_json = row
        .try_get("san_domains")
        .map_err(|e| certificate_field_error("san_domains", e))?;
    let hostnames_str: Option<String> = row
        .try_get("hostnames")
        .map_err(|e| certificate_field_error("hostnames", e))?;

    Ok(CertificateInventoryRecord {
        fingerprint,
        subject,
        issuer,
        not_before,
        not_after,
        san_json,
        hostnames: hostnames_str
            .map(|s| s.split(',').map(|h| h.to_string()).collect())
            .unwrap_or_default(),
    })
}

async fn fetch_certificate_list_postgres(
    pool: &sqlx::PgPool,
    query: &CertificateInventoryQuery,
    query_parts: &CertificateListQuery,
) -> crate::Result<Vec<CertificateInventoryRecord>> {
    let limit_placeholder = SqlDialect::Postgres.placeholder(query_parts.params.len() + 1);
    let offset_placeholder = SqlDialect::Postgres.placeholder(query_parts.params.len() + 2);
    let list_query = format!(
        r#"
        SELECT
            c.fingerprint_sha256,
            c.subject,
            c.issuer,
            c.not_before,
            c.not_after,
            c.san_domains,
            ARRAY_AGG(DISTINCT s.target_hostname) FILTER (WHERE s.target_hostname IS NOT NULL) as hostnames
        FROM certificates c
        LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
        LEFT JOIN scans s ON sc.scan_id = s.scan_id
        {}
        GROUP BY c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.not_before, c.not_after, c.san_domains
        ORDER BY {}
        LIMIT {} OFFSET {}
        "#,
        query_parts.where_clause, query_parts.order_by, limit_placeholder, offset_placeholder
    );

    let mut stmt = sqlx::query(&list_query);
    for param in &query_parts.params {
        stmt = stmt.bind(param);
    }
    let rows = stmt
        .bind(usize_to_i64(query.limit, "certificate query limit")?)
        .bind(usize_to_i64(query.offset, "certificate query offset")?)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to fetch certificates: {}", e))
        })?;

    rows.into_iter()
        .map(certificate_record_from_pg_row)
        .collect()
}

async fn fetch_certificate_list_sqlite(
    pool: &sqlx::SqlitePool,
    query: &CertificateInventoryQuery,
    query_parts: &CertificateListQuery,
) -> crate::Result<Vec<CertificateInventoryRecord>> {
    let list_query = format!(
        r#"
        SELECT
            c.fingerprint_sha256,
            c.subject,
            c.issuer,
            c.not_before,
            c.not_after,
            c.san_domains,
            GROUP_CONCAT(DISTINCT s.target_hostname) as hostnames
        FROM certificates c
        LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
        LEFT JOIN scans s ON sc.scan_id = s.scan_id
        {}
        GROUP BY c.cert_id
        ORDER BY {}
        LIMIT ? OFFSET ?
        "#,
        query_parts.where_clause, query_parts.order_by
    );

    let mut stmt = sqlx::query(&list_query);
    for param in &query_parts.params {
        stmt = stmt.bind(param);
    }
    let rows = stmt
        .bind(usize_to_i64(query.limit, "certificate query limit")?)
        .bind(usize_to_i64(query.offset, "certificate query offset")?)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to fetch certificates: {}", e))
        })?;

    rows.into_iter()
        .map(certificate_record_from_sqlite_row)
        .collect()
}

async fn fetch_certificate_detail_postgres(
    pool: &sqlx::PgPool,
    fingerprint: &str,
    principal_id: Option<&str>,
    tenant_id: Option<&str>,
) -> crate::Result<Option<CertificateInventoryRecord>> {
    let normalized_fingerprint = normalize_fingerprint_lookup(fingerprint);
    let owner_clause = principal_id.map(|_| " AND EXISTS (SELECT 1 FROM scan_certificates owner_sc JOIN scans owner_s ON owner_sc.scan_id = owner_s.scan_id WHERE owner_sc.cert_id = c.cert_id AND owner_s.principal_id = $2 AND owner_s.tenant_id IS NOT DISTINCT FROM $3)").unwrap_or("");
    let query = format!(
        r#"
        SELECT
            c.fingerprint_sha256,
            c.subject,
            c.issuer,
            c.not_before,
            c.not_after,
            c.san_domains,
            ARRAY_AGG(DISTINCT s.target_hostname) FILTER (WHERE s.target_hostname IS NOT NULL) as hostnames
        FROM certificates c
        LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
        LEFT JOIN scans s ON sc.scan_id = s.scan_id
        WHERE REPLACE(UPPER(c.fingerprint_sha256), ':', '') = $1{}
        GROUP BY c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.not_before, c.not_after, c.san_domains
        "#,
        owner_clause
    );
    let mut stmt = sqlx::query(&query).bind(normalized_fingerprint);
    if principal_id.is_some() {
        stmt = stmt.bind(principal_id).bind(tenant_id);
    }
    let row = stmt.fetch_optional(pool).await.map_err(|e| {
        crate::TlsError::DatabaseError(format!("Failed to fetch certificate: {}", e))
    })?;

    row.map(certificate_record_from_pg_row).transpose()
}

async fn fetch_certificate_detail_sqlite(
    pool: &sqlx::SqlitePool,
    fingerprint: &str,
    principal_id: Option<&str>,
    tenant_id: Option<&str>,
) -> crate::Result<Option<CertificateInventoryRecord>> {
    let normalized_fingerprint = normalize_fingerprint_lookup(fingerprint);
    let owner_clause = principal_id.map(|_| " AND EXISTS (SELECT 1 FROM scan_certificates owner_sc JOIN scans owner_s ON owner_sc.scan_id = owner_s.scan_id WHERE owner_sc.cert_id = c.cert_id AND owner_s.principal_id = ? AND owner_s.tenant_id IS ?)").unwrap_or("");
    let query = format!(
        r#"
        SELECT
            c.fingerprint_sha256,
            c.subject,
            c.issuer,
            c.not_before,
            c.not_after,
            c.san_domains,
            GROUP_CONCAT(DISTINCT s.target_hostname) as hostnames
        FROM certificates c
        LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
        LEFT JOIN scans s ON sc.scan_id = s.scan_id
        WHERE REPLACE(UPPER(c.fingerprint_sha256), ':', '') = ?{}
        GROUP BY c.cert_id
        "#,
        owner_clause
    );
    let mut stmt = sqlx::query(&query).bind(normalized_fingerprint);
    if principal_id.is_some() {
        stmt = stmt.bind(principal_id).bind(tenant_id);
    }
    let row = stmt.fetch_optional(pool).await.map_err(|e| {
        crate::TlsError::DatabaseError(format!("Failed to fetch certificate: {}", e))
    })?;

    row.map(certificate_record_from_sqlite_row).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_builder_defaults_to_expiry_ascending() {
        let query = CertificateInventoryQuery {
            limit: 50,
            offset: 0,
            sort: CertificateInventorySort::ExpiryAsc,
            hostname: None,
            expiring_within_days: None,
            principal_id: None,
            tenant_id: None,
        };
        let built = build_certificate_list_query(&query).expect("query should build");

        assert!(built.where_clause.is_empty());
        assert!(built.params.is_empty());
        assert_eq!(built.order_by, "c.not_after ASC");
    }

    #[test]
    fn query_builder_combines_filters_and_sorting() {
        let query = CertificateInventoryQuery {
            limit: 10,
            offset: 5,
            sort: CertificateInventorySort::IssuedDesc,
            hostname: Some("example.com".to_string()),
            expiring_within_days: Some(30),
            principal_id: None,
            tenant_id: None,
        };
        let built = build_certificate_list_query(&query).expect("query should build");

        assert!(built.where_clause.contains("LOWER(s.target_hostname) = ?"));
        assert!(
            built
                .where_clause
                .contains("datetime(c.not_after) <= datetime(?)")
        );
        assert_eq!(built.params.len(), 2);
        assert_eq!(built.params[0], "example.com");
        assert_eq!(built.order_by, "c.not_before DESC");
    }

    #[test]
    fn query_builder_uses_case_insensitive_hostname_filter() {
        let query = CertificateInventoryQuery {
            limit: 10,
            offset: 0,
            sort: CertificateInventorySort::ExpiryAsc,
            hostname: Some("example.com".to_string()),
            expiring_within_days: None,
            principal_id: None,
            tenant_id: None,
        };

        let built = build_certificate_list_query(&query).expect("query should build");

        assert!(built.where_clause.contains("LOWER(s.target_hostname) = ?"));
    }

    #[test]
    fn query_builder_uses_postgres_placeholders_for_postgres_filters() {
        let query = CertificateInventoryQuery {
            limit: 10,
            offset: 5,
            sort: CertificateInventorySort::ExpiryAsc,
            hostname: Some("example.com".to_string()),
            expiring_within_days: Some(30),
            principal_id: None,
            tenant_id: None,
        };

        let built = build_certificate_list_query_for_dialect(&query, SqlDialect::Postgres)
            .expect("query should build");

        assert!(built.where_clause.contains("LOWER(s.target_hostname) = $1"));
        assert!(built.where_clause.contains("c.not_after <= $2"));
        assert!(!built.where_clause.contains('?'));
        assert_eq!(built.params.len(), 2);
    }

    #[test]
    fn query_builder_rejects_out_of_range_expiry_window() {
        let query = CertificateInventoryQuery {
            limit: 10,
            offset: 0,
            sort: CertificateInventorySort::ExpiryAsc,
            hostname: None,
            expiring_within_days: Some(u32::MAX),
            principal_id: None,
            tenant_id: None,
        };

        let err = match build_certificate_list_query(&query) {
            Ok(_) => panic!("oversized expiry window should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("expiring_within_days"));
    }

    #[test]
    fn fingerprint_lookup_normalization_ignores_case_and_colons() {
        assert_eq!(
            normalize_fingerprint_lookup("aa:BB:00:ff"),
            normalize_fingerprint_lookup("AABB00FF")
        );
    }

    #[tokio::test]
    async fn inventory_service_wraps_database_pool() {
        let pool = DatabasePool::Sqlite(sqlx::SqlitePool::connect(":memory:").await.expect("pool"));
        let service = CertificateInventoryService::new(&pool);
        let query = CertificateInventoryQuery {
            limit: 10,
            offset: 0,
            sort: CertificateInventorySort::ExpiryAsc,
            hostname: None,
            expiring_within_days: None,
            principal_id: None,
            tenant_id: None,
        };

        let future = service.list_certificates(&query);
        std::mem::drop(future);
    }

    #[tokio::test]
    #[cfg(feature = "db-postgres")]
    async fn postgres_inventory_queries_cover_filters_ordering_and_owner_scope() {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::str::FromStr;

        let Ok(url) = std::env::var("CIPHERRUN_TEST_POSTGRES_URL") else {
            return;
        };
        let admin = PgPoolOptions::new()
            .connect_with(PgConnectOptions::from_str(&url).expect("test URL should be valid"))
            .await
            .expect("test PostgreSQL should accept connections");
        let schema = format!("cipherrun_test_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("test schema should be created");
        let options = PgConnectOptions::from_str(&url)
            .expect("test URL should be valid")
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .connect_with(options)
            .await
            .expect("test schema should accept connections");
        let database = DatabasePool::Postgres(pool.clone());
        sqlx::query(
            "CREATE TABLE certificates (cert_id BIGINT PRIMARY KEY, fingerprint_sha256 TEXT, subject TEXT, issuer TEXT, not_before TIMESTAMPTZ, not_after TIMESTAMPTZ, san_domains TEXT)",
        )
        .execute(&pool)
        .await
        .expect("test certificates table should be created");
        sqlx::query(
            "CREATE TABLE scans (scan_id BIGINT PRIMARY KEY, target_hostname TEXT, principal_id TEXT, tenant_id TEXT)",
        )
        .execute(&pool)
        .await
        .expect("test scans table should be created");
        sqlx::query("CREATE TABLE scan_certificates (scan_id BIGINT, cert_id BIGINT)")
            .execute(&pool)
            .await
            .expect("test scan certificates table should be created");

        let now = Utc::now();
        for (id, fingerprint, expiry) in [
            (1_i64, "AA:BB", now + chrono::Duration::days(10)),
            (2_i64, "CC:DD", now + chrono::Duration::days(300)),
        ] {
            sqlx::query(
                "INSERT INTO certificates VALUES ($1, $2, 'subject', 'issuer', $3, $4, NULL)",
            )
            .bind(id)
            .bind(fingerprint)
            .bind(now - chrono::Duration::days(10))
            .bind(expiry)
            .execute(&pool)
            .await
            .expect("test certificate should insert");
        }
        for (scan_id, hostname, principal_id, tenant_id, cert_id) in [
            (1_i64, "example.com", "alice", Some("tenant-a"), 1_i64),
            (2_i64, "public.example", "bob", None, 2_i64),
        ] {
            sqlx::query("INSERT INTO scans VALUES ($1, $2, $3, $4)")
                .bind(scan_id)
                .bind(hostname)
                .bind(principal_id)
                .bind(tenant_id)
                .execute(&pool)
                .await
                .expect("test scan should insert");
            sqlx::query("INSERT INTO scan_certificates VALUES ($1, $2)")
                .bind(scan_id)
                .bind(cert_id)
                .execute(&pool)
                .await
                .expect("test certificate association should insert");
        }

        let page = list_certificates(
            &database,
            &CertificateInventoryQuery {
                limit: 10,
                offset: 0,
                sort: CertificateInventorySort::ExpiryAsc,
                hostname: Some("example.com".to_string()),
                expiring_within_days: Some(30),
                principal_id: Some("alice".to_string()),
                tenant_id: Some("tenant-a".to_string()),
            },
        )
        .await
        .expect("filtered inventory query should succeed");
        assert_eq!(page.total, 1);
        assert_eq!(page.certificates[0].fingerprint, "AA:BB");
        assert_eq!(page.certificates[0].hostnames, ["example.com"]);

        let tenantless = get_certificate_for_owner(&database, "cc:dd", Some("bob"), None)
            .await
            .expect("tenantless owner lookup should succeed");
        assert_eq!(
            tenantless
                .expect("owner should see certificate")
                .fingerprint,
            "CC:DD"
        );
        assert!(
            get_certificate_for_owner(&database, "cc:dd", Some("alice"), Some("tenant-a"))
                .await
                .expect("non-owner lookup should succeed")
                .is_none()
        );
        assert_eq!(
            get_certificate(&database, "aa:bb")
                .await
                .expect("normalized fingerprint lookup should succeed")
                .expect("certificate should exist")
                .hostnames,
            ["example.com"]
        );
        assert!(
            get_certificate(&database, "missing")
                .await
                .expect("missing fingerprint lookup should succeed")
                .is_none()
        );

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .expect("test schema should be removed");
        admin.close().await;
    }
}
