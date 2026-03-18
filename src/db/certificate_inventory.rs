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
    async fn list_certificates(
        &self,
        query: &CertificateInventoryQuery,
    ) -> crate::Result<CertificateInventoryPage> {
        list_certificates(self.pool, query).await
    }

    async fn get_certificate(
        &self,
        fingerprint: &str,
    ) -> crate::Result<Option<CertificateInventoryRecord>> {
        get_certificate(self.pool, fingerprint).await
    }
}

struct CertificateListQuery {
    where_clause: String,
    params: Vec<String>,
    order_by: &'static str,
}

pub async fn list_certificates(
    pool: &DatabasePool,
    query: &CertificateInventoryQuery,
) -> crate::Result<CertificateInventoryPage> {
    let query_parts = build_certificate_list_query(query);

    let (total, certificates) = match pool {
        DatabasePool::Postgres(pool) => (
            fetch_certificate_count_postgres(pool, &query_parts).await?,
            fetch_certificate_list_postgres(pool, query, &query_parts).await?,
        ),
        DatabasePool::Sqlite(pool) => (
            fetch_certificate_count_sqlite(pool, &query_parts).await?,
            fetch_certificate_list_sqlite(pool, query, &query_parts).await?,
        ),
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
        DatabasePool::Postgres(pool) => fetch_certificate_detail_postgres(pool, fingerprint).await,
        DatabasePool::Sqlite(pool) => fetch_certificate_detail_sqlite(pool, fingerprint).await,
    }
}

fn build_certificate_list_query(query: &CertificateInventoryQuery) -> CertificateListQuery {
    let mut where_clauses = Vec::new();
    let mut params = Vec::new();

    if let Some(ref hostname) = query.hostname {
        where_clauses.push("EXISTS (SELECT 1 FROM scan_certificates sc JOIN scans s ON sc.scan_id = s.scan_id WHERE sc.cert_id = c.cert_id AND s.target_hostname = ?)");
        params.push(hostname.clone());
    }

    if let Some(days) = query.expiring_within_days {
        let cutoff_date = Utc::now() + chrono::Duration::days(days as i64);
        where_clauses.push("c.not_after <= ?");
        params.push(cutoff_date.to_rfc3339());
    }

    let where_clause = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    CertificateListQuery {
        where_clause,
        params,
        order_by: query.sort.as_order_by(),
    }
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
    Ok(total as usize)
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
    Ok(total as usize)
}

fn certificate_record_from_pg_row(row: PgRow) -> CertificateInventoryRecord {
    let fingerprint: String = row.get("fingerprint_sha256");
    let subject: String = row.get("subject");
    let issuer: String = row.get("issuer");
    let not_before: chrono::DateTime<Utc> = row.get("not_before");
    let not_after: chrono::DateTime<Utc> = row.get("not_after");
    let san_json: Option<String> = row.try_get("san_domains").ok();
    let hostnames: Option<Vec<String>> = row.try_get("hostnames").ok();

    CertificateInventoryRecord {
        fingerprint,
        subject,
        issuer,
        not_before,
        not_after,
        san_json,
        hostnames: hostnames.unwrap_or_default(),
    }
}

fn certificate_record_from_sqlite_row(row: SqliteRow) -> CertificateInventoryRecord {
    let fingerprint: String = row.get("fingerprint_sha256");
    let subject: String = row.get("subject");
    let issuer: String = row.get("issuer");
    let not_before: chrono::DateTime<Utc> = row.get("not_before");
    let not_after: chrono::DateTime<Utc> = row.get("not_after");
    let san_json: Option<String> = row.try_get("san_domains").ok();
    let hostnames_str: Option<String> = row.try_get("hostnames").ok();

    CertificateInventoryRecord {
        fingerprint,
        subject,
        issuer,
        not_before,
        not_after,
        san_json,
        hostnames: hostnames_str
            .map(|s| s.split(',').map(|h| h.to_string()).collect())
            .unwrap_or_default(),
    }
}

async fn fetch_certificate_list_postgres(
    pool: &sqlx::PgPool,
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
            ARRAY_AGG(DISTINCT s.target_hostname) as hostnames
        FROM certificates c
        LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
        LEFT JOIN scans s ON sc.scan_id = s.scan_id
        {}
        GROUP BY c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.not_before, c.not_after, c.san_domains
        ORDER BY {}
        LIMIT $1 OFFSET $2
        "#,
        query_parts.where_clause, query_parts.order_by
    );

    let rows = sqlx::query(&list_query)
        .bind(query.limit as i64)
        .bind(query.offset as i64)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to fetch certificates: {}", e))
        })?;

    Ok(rows
        .into_iter()
        .map(certificate_record_from_pg_row)
        .collect())
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
        .bind(query.limit as i64)
        .bind(query.offset as i64)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            crate::TlsError::DatabaseError(format!("Failed to fetch certificates: {}", e))
        })?;

    Ok(rows
        .into_iter()
        .map(certificate_record_from_sqlite_row)
        .collect())
}

async fn fetch_certificate_detail_postgres(
    pool: &sqlx::PgPool,
    fingerprint: &str,
) -> crate::Result<Option<CertificateInventoryRecord>> {
    let row = sqlx::query(
        r#"
        SELECT
            c.fingerprint_sha256,
            c.subject,
            c.issuer,
            c.not_before,
            c.not_after,
            c.san_domains,
            ARRAY_AGG(DISTINCT s.target_hostname) as hostnames
        FROM certificates c
        LEFT JOIN scan_certificates sc ON c.cert_id = sc.cert_id
        LEFT JOIN scans s ON sc.scan_id = s.scan_id
        WHERE c.fingerprint_sha256 = $1
        GROUP BY c.cert_id, c.fingerprint_sha256, c.subject, c.issuer, c.not_before, c.not_after, c.san_domains
        "#,
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await
    .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch certificate: {}", e)))?;

    Ok(row.map(certificate_record_from_pg_row))
}

async fn fetch_certificate_detail_sqlite(
    pool: &sqlx::SqlitePool,
    fingerprint: &str,
) -> crate::Result<Option<CertificateInventoryRecord>> {
    let row = sqlx::query(
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
        WHERE c.fingerprint_sha256 = ?
        GROUP BY c.cert_id
        "#,
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await
    .map_err(|e| crate::TlsError::DatabaseError(format!("Failed to fetch certificate: {}", e)))?;

    Ok(row.map(certificate_record_from_sqlite_row))
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
        };
        let built = build_certificate_list_query(&query);

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
        };
        let built = build_certificate_list_query(&query);

        assert!(built.where_clause.contains("s.target_hostname = ?"));
        assert!(built.where_clause.contains("c.not_after <= ?"));
        assert_eq!(built.params.len(), 2);
        assert_eq!(built.params[0], "example.com");
        assert_eq!(built.order_by, "c.not_before DESC");
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
        };

        let future = service.list_certificates(&query);
        std::mem::drop(future);
    }
}
