use super::{JobQueue, ScanJob};
use crate::api::models::response::ScanStatus;
use crate::db::DatabasePool;
use crate::{Result, tls_bail};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sqlx::Row;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

const TABLE: &str = "cipherrun_jobs";
const LEASE_SECONDS: i64 = 3600;

/// SQL-backed queue shared by standalone SQLite and distributed PostgreSQL deployments.
pub struct DatabaseJobQueue {
    pool: Arc<DatabasePool>,
    max_capacity: usize,
    retention: Option<Duration>,
    claim_lock: Mutex<()>,
}

impl DatabaseJobQueue {
    pub fn new(
        pool: Arc<DatabasePool>,
        max_capacity: usize,
        retention: Option<Duration>,
    ) -> Arc<Self> {
        Arc::new(Self {
            pool,
            max_capacity,
            retention,
            claim_lock: Mutex::new(()),
        })
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "job_queue.ensure_schema"
        )
    )]
    async fn ensure_schema(&self) -> Result<()> {
        let sqlite = format!(
            "CREATE TABLE IF NOT EXISTS {TABLE} (\
             id TEXT PRIMARY KEY, status TEXT NOT NULL, queued_at TIMESTAMP NOT NULL,\
             job_json TEXT NOT NULL, principal_id TEXT NOT NULL DEFAULT '',\
             tenant_id TEXT NOT NULL DEFAULT '',\
             idempotency_key TEXT, request_fingerprint TEXT, lease_until TIMESTAMP,\
             attempts INTEGER NOT NULL DEFAULT 0)"
        );
        let postgres = format!(
            "CREATE TABLE IF NOT EXISTS {TABLE} (\
             id TEXT PRIMARY KEY, status TEXT NOT NULL, queued_at TIMESTAMPTZ NOT NULL,\
             job_json TEXT NOT NULL, principal_id TEXT NOT NULL DEFAULT '',\
             tenant_id TEXT NOT NULL DEFAULT '',\
             idempotency_key TEXT, request_fingerprint TEXT, lease_until TIMESTAMPTZ,\
             attempts INTEGER NOT NULL DEFAULT 0)"
        );
        match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(&sqlite).execute(pool).await.map_err(db_error)?;
                let columns = sqlx::query("PRAGMA table_info(cipherrun_jobs)")
                    .fetch_all(pool)
                    .await
                    .map_err(db_error)?;
                let has_tenant = columns.iter().any(|row| {
                    row.try_get::<String, _>("name")
                        .map(|name| name == "tenant_id")
                        .unwrap_or(false)
                });
                if !has_tenant {
                    sqlx::query(
                        "ALTER TABLE cipherrun_jobs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''",
                    )
                    .execute(pool)
                    .await
                    .map_err(db_error)?;
                }
                sqlx::query("DROP INDEX IF EXISTS idx_cipherrun_jobs_idempotency")
                    .execute(pool)
                    .await
                    .map_err(db_error)?;
                sqlx::query(&format!(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_{TABLE}_idempotency \
                     ON {TABLE}(tenant_id, principal_id, idempotency_key)"
                ))
                .execute(pool)
                .await
                .map_err(db_error)?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(&postgres)
                    .execute(pool)
                    .await
                    .map_err(db_error)?;
                sqlx::query(&format!(
                    "ALTER TABLE {TABLE} ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT ''"
                ))
                .execute(pool)
                .await
                .map_err(db_error)?;
                sqlx::query(&format!("DROP INDEX IF EXISTS idx_{TABLE}_idempotency"))
                    .execute(pool)
                    .await
                    .map_err(db_error)?;
                sqlx::query(&format!(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_{TABLE}_idempotency \
                     ON {TABLE}(tenant_id, principal_id, idempotency_key)"
                ))
                .execute(pool)
                .await
                .map_err(db_error)?;
            }
        }
        self.recover_expired_leases().await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "job_queue.recover_expired_leases"
        )
    )]
    async fn recover_expired_leases(&self) -> Result<()> {
        let started = Instant::now();
        let now = Utc::now();
        let query = format!(
            "UPDATE {TABLE} SET status = 'queued', lease_until = NULL \
             WHERE status = 'running' AND lease_until IS NOT NULL AND lease_until < {}",
            placeholder(self.pool.as_ref(), 1)
        );
        let recovered_expired_leases = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query(&query)
                .bind(now)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
            DatabasePool::Postgres(pool) => sqlx::query(&query)
                .bind(now)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
        }
        .map_err(db_error)?;

        let query = format!("SELECT id, job_json FROM {TABLE} WHERE status = 'queued'");
        let rows: Vec<(String, String)> = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query(&query)
                .fetch_all(pool)
                .await
                .map_err(db_error)?
                .into_iter()
                .map(|row| {
                    Ok((
                        row.try_get("id").map_err(db_error)?,
                        row.try_get("job_json").map_err(db_error)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
            DatabasePool::Postgres(pool) => sqlx::query(&query)
                .fetch_all(pool)
                .await
                .map_err(db_error)?
                .into_iter()
                .map(|row| {
                    Ok((
                        row.try_get("id").map_err(db_error)?,
                        row.try_get("job_json").map_err(db_error)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        };
        let mut recovered_serialized_jobs = 0;
        for (id, json) in rows {
            let Ok(mut job) = serde_json::from_str::<ScanJob>(&json) else {
                continue;
            };
            if !matches!(job.status, ScanStatus::Running) {
                continue;
            }
            job.mark_queued();
            let update = format!(
                "UPDATE {TABLE} SET job_json = {} WHERE id = {}",
                placeholder(self.pool.as_ref(), 1),
                placeholder(self.pool.as_ref(), 2)
            );
            let json = serde_json::to_string(&job)?;
            recovered_serialized_jobs += match self.pool.as_ref() {
                DatabasePool::Sqlite(pool) => sqlx::query(&update)
                    .bind(json)
                    .bind(&id)
                    .execute(pool)
                    .await
                    .map(|result| result.rows_affected())
                    .map_err(db_error)?,
                DatabasePool::Postgres(pool) => sqlx::query(&update)
                    .bind(json)
                    .bind(&id)
                    .execute(pool)
                    .await
                    .map(|result| result.rows_affected())
                    .map_err(db_error)?,
            };
        }
        if recovered_expired_leases > 0 || recovered_serialized_jobs > 0 {
            tracing::info!(
                event_name = "scan_jobs.database.recovered",
                component = "api.jobs.database",
                operation = "recover_expired_leases",
                recovered_expired_leases,
                recovered_serialized_jobs,
                duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                outcome = "success",
                "Recovered persisted scan jobs"
            );
        }
        Ok(())
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "job_queue.active_count"
        )
    )]
    async fn active_count(&self) -> Result<i64> {
        let query = format!("SELECT COUNT(*) FROM {TABLE} WHERE status IN ('queued','running')");
        match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query_scalar(&query).fetch_one(pool).await,
            DatabasePool::Postgres(pool) => sqlx::query_scalar(&query).fetch_one(pool).await,
        }
        .map_err(db_error)
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.load")
    )]
    async fn load(&self, id: &str) -> Result<Option<ScanJob>> {
        let query = format!(
            "SELECT job_json FROM {TABLE} WHERE id = {}",
            placeholder(self.pool.as_ref(), 1)
        );
        let json = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_scalar::<_, String>(&query)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(&query)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
        }
        .map_err(db_error)?;
        json.map(|json| {
            serde_json::from_str(&json).map_err(|error| crate::TlsError::ParseError {
                message: format!("Invalid persisted database job {id}: {error}"),
            })
        })
        .transpose()
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.update_row")
    )]
    async fn update_row(&self, job: &ScanJob, lease_until: Option<DateTime<Utc>>) -> Result<()> {
        let json = serde_json::to_string(job)?;
        let status = if job.dead_letter {
            "dead_letter"
        } else {
            status_name(job.status)
        };
        let query = format!(
            "UPDATE {TABLE} SET status = {}, job_json = {}, lease_until = {}, attempts = {} WHERE id = {}",
            placeholder(self.pool.as_ref(), 1),
            placeholder(self.pool.as_ref(), 2),
            placeholder(self.pool.as_ref(), 3),
            placeholder(self.pool.as_ref(), 4),
            placeholder(self.pool.as_ref(), 5)
        );
        match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query(&query)
                .bind(status)
                .bind(json)
                .bind(lease_until)
                .bind(i64::from(job.attempts))
                .bind(&job.id)
                .execute(pool)
                .await
                .map(|_| ()),
            DatabasePool::Postgres(pool) => sqlx::query(&query)
                .bind(status)
                .bind(json)
                .bind(lease_until)
                .bind(i64::from(job.attempts))
                .bind(&job.id)
                .execute(pool)
                .await
                .map(|_| ()),
        }
        .map_err(db_error)
    }
}

#[async_trait]
impl JobQueue for DatabaseJobQueue {
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.enqueue")
    )]
    async fn enqueue(&self, job: ScanJob) -> Result<String> {
        self.ensure_schema().await?;
        if self.active_count().await? >= i64::try_from(self.max_capacity).unwrap_or(i64::MAX) {
            tls_bail!("Job queue is full");
        }
        if let Some(key) = job.idempotency_key.as_deref() {
            let query = format!(
                "SELECT id, request_fingerprint FROM {TABLE} WHERE tenant_id = {} AND principal_id = {} AND idempotency_key = {}",
                placeholder(self.pool.as_ref(), 1),
                placeholder(self.pool.as_ref(), 2),
                placeholder(self.pool.as_ref(), 3)
            );
            let existing: Option<(String, Option<String>)> = match self.pool.as_ref() {
                DatabasePool::Sqlite(pool) => sqlx::query(&query)
                    .bind(job.tenant_id.as_deref().unwrap_or(""))
                    .bind(&job.principal_id)
                    .bind(key)
                    .fetch_optional(pool)
                    .await
                    .map_err(db_error)?
                    .map(|row| -> Result<(String, Option<String>)> {
                        Ok((
                            row.try_get("id").map_err(db_error)?,
                            row.try_get("request_fingerprint").map_err(db_error)?,
                        ))
                    })
                    .transpose()?,
                DatabasePool::Postgres(pool) => sqlx::query(&query)
                    .bind(job.tenant_id.as_deref().unwrap_or(""))
                    .bind(&job.principal_id)
                    .bind(key)
                    .fetch_optional(pool)
                    .await
                    .map_err(db_error)?
                    .map(|row| -> Result<(String, Option<String>)> {
                        Ok((
                            row.try_get("id").map_err(db_error)?,
                            row.try_get("request_fingerprint").map_err(db_error)?,
                        ))
                    })
                    .transpose()?,
            };
            if let Some((id, fingerprint)) = existing {
                if fingerprint == job.request_fingerprint {
                    return Ok(id);
                }
                return Err(crate::TlsError::InvalidInput {
                    message: "Idempotency-Key was already used with a different scan request"
                        .to_string(),
                });
            }
        }

        let json = serde_json::to_string(&job)?;
        let query = format!(
            "INSERT INTO {TABLE} (id,status,queued_at,job_json,principal_id,tenant_id,idempotency_key,request_fingerprint,lease_until,attempts) \
             VALUES ({},{},{},{},{},{},{},{},NULL,0) ON CONFLICT DO NOTHING",
            placeholder(self.pool.as_ref(), 1),
            placeholder(self.pool.as_ref(), 2),
            placeholder(self.pool.as_ref(), 3),
            placeholder(self.pool.as_ref(), 4),
            placeholder(self.pool.as_ref(), 5),
            placeholder(self.pool.as_ref(), 6),
            placeholder(self.pool.as_ref(), 7),
            placeholder(self.pool.as_ref(), 8)
        );
        let rows_affected = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query(&query)
                .bind(&job.id)
                .bind(status_name(job.status))
                .bind(job.queued_at)
                .bind(json)
                .bind(&job.principal_id)
                .bind(job.tenant_id.as_deref().unwrap_or(""))
                .bind(&job.idempotency_key)
                .bind(&job.request_fingerprint)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
            DatabasePool::Postgres(pool) => sqlx::query(&query)
                .bind(&job.id)
                .bind(status_name(job.status))
                .bind(job.queued_at)
                .bind(json)
                .bind(&job.principal_id)
                .bind(job.tenant_id.as_deref().unwrap_or(""))
                .bind(&job.idempotency_key)
                .bind(&job.request_fingerprint)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
        }
        .map_err(db_error)?;
        if rows_affected == 0 {
            return Err(crate::TlsError::Other(format!(
                "Job already exists: {}",
                job.id
            )));
        }
        Ok(job.id)
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.dequeue")
    )]
    async fn dequeue(&self) -> Result<Option<ScanJob>> {
        self.ensure_schema().await?;
        let _guard = self.claim_lock.lock().await;
        for _ in 0..10 {
            let select = format!(
                "SELECT id FROM {TABLE} WHERE status = 'queued' ORDER BY queued_at ASC LIMIT 1"
            );
            let id: Option<String> = match self.pool.as_ref() {
                DatabasePool::Sqlite(pool) => {
                    sqlx::query_scalar(&select).fetch_optional(pool).await
                }
                DatabasePool::Postgres(pool) => {
                    sqlx::query_scalar(&select).fetch_optional(pool).await
                }
            }
            .map_err(db_error)?;
            let Some(id) = id else {
                return Ok(None);
            };
            let update = format!(
                "UPDATE {TABLE} SET status = 'running', lease_until = {} \
                 WHERE id = {} AND status = 'queued'",
                placeholder(self.pool.as_ref(), 1),
                placeholder(self.pool.as_ref(), 2)
            );
            let lease = Utc::now() + Duration::seconds(LEASE_SECONDS);
            let claimed = match self.pool.as_ref() {
                DatabasePool::Sqlite(pool) => sqlx::query(&update)
                    .bind(lease)
                    .bind(&id)
                    .execute(pool)
                    .await
                    .map(|result| result.rows_affected()),
                DatabasePool::Postgres(pool) => sqlx::query(&update)
                    .bind(lease)
                    .bind(&id)
                    .execute(pool)
                    .await
                    .map(|result| result.rows_affected()),
            }
            .map_err(db_error)?;
            if claimed != 1 {
                continue;
            }
            let mut job = self.load(&id).await?.ok_or_else(|| {
                crate::TlsError::DatabaseError("Claimed job disappeared".to_string())
            })?;
            job.mark_started();
            self.update_row(&job, Some(lease)).await?;
            return Ok(Some(job));
        }
        Ok(None)
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.get")
    )]
    async fn get_job(&self, id: &str) -> Result<Option<ScanJob>> {
        self.ensure_schema().await?;
        self.load(id).await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.update")
    )]
    async fn update_job(&self, job: &ScanJob) -> Result<()> {
        self.ensure_schema().await?;
        let lease = if matches!(job.status, ScanStatus::Running) {
            Some(Utc::now() + Duration::seconds(LEASE_SECONDS))
        } else {
            None
        };
        self.update_row(job, lease).await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "job_queue.update_preserving_cancelled"
        )
    )]
    async fn update_job_preserving_cancelled(&self, job: &ScanJob) -> Result<bool> {
        self.ensure_schema().await?;
        let json = serde_json::to_string(job)?;
        let query = format!(
            "UPDATE {TABLE} SET status = {}, job_json = {}, lease_until = {}, attempts = {} \
             WHERE id = {} AND status <> 'cancelled'",
            placeholder(self.pool.as_ref(), 1),
            placeholder(self.pool.as_ref(), 2),
            placeholder(self.pool.as_ref(), 3),
            placeholder(self.pool.as_ref(), 4),
            placeholder(self.pool.as_ref(), 5)
        );
        let lease = if matches!(job.status, ScanStatus::Running) {
            Some(Utc::now() + Duration::seconds(LEASE_SECONDS))
        } else {
            None
        };
        let updated = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query(&query)
                .bind(status_name(job.status))
                .bind(json)
                .bind(lease)
                .bind(i64::from(job.attempts))
                .bind(&job.id)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
            DatabasePool::Postgres(pool) => sqlx::query(&query)
                .bind(status_name(job.status))
                .bind(json)
                .bind(lease)
                .bind(i64::from(job.attempts))
                .bind(&job.id)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
        }
        .map_err(db_error)?;
        Ok(updated == 1)
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.renew_lease")
    )]
    async fn renew_lease(&self, id: &str) -> Result<bool> {
        self.ensure_schema().await?;
        let query = format!(
            "UPDATE {TABLE} SET lease_until = {} WHERE id = {} AND status = 'running'",
            placeholder(self.pool.as_ref(), 1),
            placeholder(self.pool.as_ref(), 2)
        );
        let lease = Utc::now() + Duration::seconds(LEASE_SECONDS);
        let affected = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query(&query)
                .bind(lease)
                .bind(id)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
            DatabasePool::Postgres(pool) => sqlx::query(&query)
                .bind(lease)
                .bind(id)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
        }
        .map_err(db_error)?;
        Ok(affected == 1)
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "job_queue.retry_or_dead_letter"
        )
    )]
    async fn retry_or_dead_letter(
        &self,
        job: &ScanJob,
        error: &str,
        max_attempts: u32,
    ) -> Result<super::RetryDisposition> {
        self.ensure_schema().await?;
        let mut next = self.load(&job.id).await?.ok_or_else(|| {
            crate::TlsError::DatabaseError(format!("Retry job disappeared: {}", job.id))
        })?;
        if next.attempts < max_attempts {
            next.error = Some(error.to_string());
            next.mark_queued();
            self.update_row(&next, None).await?;
            Ok(super::RetryDisposition::Requeued)
        } else {
            next.mark_dead_letter(error);
            self.update_row(&next, None).await?;
            let query = format!(
                "UPDATE {TABLE} SET status = 'dead_letter' WHERE id = {}",
                placeholder(self.pool.as_ref(), 1)
            );
            match self.pool.as_ref() {
                DatabasePool::Sqlite(pool) => sqlx::query(&query)
                    .bind(&next.id)
                    .execute(pool)
                    .await
                    .map(|_| ()),
                DatabasePool::Postgres(pool) => sqlx::query(&query)
                    .bind(&next.id)
                    .execute(pool)
                    .await
                    .map(|_| ()),
            }
            .map_err(db_error)?;
            Ok(super::RetryDisposition::DeadLettered)
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.cancel")
    )]
    async fn cancel_job(&self, id: &str) -> Result<bool> {
        self.ensure_schema().await?;
        let Some(mut job) = self.load(id).await? else {
            return Ok(false);
        };
        if !matches!(job.status, ScanStatus::Queued | ScanStatus::Running) {
            return Ok(false);
        }
        job.mark_cancelled();
        let query = format!(
            "UPDATE {TABLE} SET status = 'cancelled', job_json = {}, lease_until = NULL \
             WHERE id = {} AND status IN ('queued','running')",
            placeholder(self.pool.as_ref(), 1),
            placeholder(self.pool.as_ref(), 2)
        );
        let json = serde_json::to_string(&job)?;
        let result = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query(&query)
                .bind(json)
                .bind(id)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
            DatabasePool::Postgres(pool) => sqlx::query(&query)
                .bind(json)
                .bind(id)
                .execute(pool)
                .await
                .map(|result| result.rows_affected()),
        }
        .map_err(db_error)?;
        Ok(result == 1)
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.length")
    )]
    async fn queue_length(&self) -> Result<usize> {
        self.ensure_schema().await?;
        let query = format!("SELECT COUNT(*) FROM {TABLE} WHERE status = 'queued'");
        let count: i64 = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query_scalar(&query).fetch_one(pool).await,
            DatabasePool::Postgres(pool) => sqlx::query_scalar(&query).fetch_one(pool).await,
        }
        .map_err(db_error)?;
        usize::try_from(count)
            .map_err(|_| crate::TlsError::DatabaseError("Invalid queue count".to_string()))
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(event_name = "database.operation", operation = "job_queue.list")
    )]
    async fn list_jobs(&self) -> Result<Vec<ScanJob>> {
        self.ensure_schema().await?;
        let query = format!("SELECT job_json FROM {TABLE} ORDER BY queued_at ASC");
        let rows = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query_scalar::<_, String>(&query)
                    .fetch_all(pool)
                    .await
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(&query)
                    .fetch_all(pool)
                    .await
            }
        }
        .map_err(db_error)?;
        rows.into_iter()
            .map(|json| {
                serde_json::from_str(&json).map_err(|error| crate::TlsError::ParseError {
                    message: error.to_string(),
                })
            })
            .collect()
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "job_queue.active_jobs_count"
        )
    )]
    async fn active_jobs_count(&self) -> Result<usize> {
        self.ensure_schema().await?;
        let count = self.active_count().await?;
        usize::try_from(count)
            .map_err(|_| crate::TlsError::DatabaseError("Invalid active count".to_string()))
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            event_name = "database.operation",
            operation = "job_queue.prune_expired"
        )
    )]
    async fn prune_expired(&self) -> Result<usize> {
        let Some(retention) = self.retention else {
            return Ok(0);
        };
        let cutoff = Utc::now() - retention;
        let jobs = self.list_jobs().await?;
        let expired: Vec<String> = jobs
            .into_iter()
            .filter(|job| {
                matches!(
                    job.status,
                    ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
                ) && job
                    .completed_at
                    .is_some_and(|completed| completed <= cutoff)
            })
            .map(|job| job.id)
            .collect();
        for id in &expired {
            let query = format!(
                "DELETE FROM {TABLE} WHERE id = {}",
                placeholder(self.pool.as_ref(), 1)
            );
            match self.pool.as_ref() {
                DatabasePool::Sqlite(pool) => {
                    sqlx::query(&query).bind(id).execute(pool).await.map(|_| ())
                }
                DatabasePool::Postgres(pool) => {
                    sqlx::query(&query).bind(id).execute(pool).await.map(|_| ())
                }
            }
            .map_err(db_error)?;
        }
        Ok(expired.len())
    }
}

fn status_name(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::Queued => "queued",
        ScanStatus::Running => "running",
        ScanStatus::Completed => "completed",
        ScanStatus::Failed => "failed",
        ScanStatus::Cancelled => "cancelled",
    }
}

fn placeholder(pool: &DatabasePool, index: usize) -> String {
    match pool {
        DatabasePool::Sqlite(_) => "?".to_string(),
        DatabasePool::Postgres(_) => format!("${index}"),
    }
}

fn db_error(error: sqlx::Error) -> crate::TlsError {
    crate::TlsError::DatabaseError(format!("Database job queue error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{DatabaseConfig, DatabasePool};

    #[tokio::test]
    async fn sqlite_database_queue_persists_and_recovers_jobs() {
        use std::io::Write;
        use std::sync::Mutex as StdMutex;

        struct CapturedWriter(Arc<StdMutex<Vec<u8>>>);

        impl Write for CapturedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            DatabasePool::new(&DatabaseConfig::sqlite(directory.path().join("jobs.db")))
                .await
                .unwrap(),
        );
        let queue = DatabaseJobQueue::new(pool, 10, Some(Duration::days(7)));
        let job = ScanJob::new("example.com:443".to_string(), Default::default(), None);
        let id = queue.enqueue(job).await.unwrap();
        let claimed = queue.dequeue().await.unwrap().unwrap();
        assert_eq!(claimed.id, id);
        assert_eq!(claimed.status, ScanStatus::Running);
        assert_eq!(claimed.attempts, 1);
        assert!(queue.renew_lease(&id).await.unwrap());
        assert_eq!(queue.active_jobs_count().await.unwrap(), 1);

        if let DatabasePool::Sqlite(pool) = queue.pool.as_ref() {
            sqlx::query("UPDATE cipherrun_jobs SET lease_until = ? WHERE id = ?")
                .bind(Utc::now() - Duration::hours(2))
                .bind(&id)
                .execute(pool)
                .await
                .unwrap();
        }
        let recovered = DatabaseJobQueue::new(queue.pool.clone(), 10, Some(Duration::days(7)));
        let output = Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer({
                let output = output.clone();
                move || CapturedWriter(output.clone())
            })
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let recovered_job = recovered.get_job(&id).await.unwrap().unwrap();
        assert_eq!(recovered_job.status, ScanStatus::Queued);
        assert!(recovered_job.started_at.is_none());

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(output.contains("scan_jobs.database.recovered"), "{output}");
        assert!(output.contains("recovered_expired_leases=1"), "{output}");
        assert!(output.contains("recovered_serialized_jobs=1"), "{output}");
        assert!(output.contains("outcome=\"success\""), "{output}");
        assert!(!output.contains("example.com"), "{output}");
    }

    #[tokio::test]
    async fn sqlite_idempotency_is_scoped_by_tenant_and_principal() {
        let directory = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            DatabasePool::new(&DatabaseConfig::sqlite(directory.path().join("jobs.db")))
                .await
                .unwrap(),
        );
        let queue = DatabaseJobQueue::new(pool, 10, None);

        let mut tenant_a = ScanJob::new_owned(
            "example.com:443".to_string(),
            Default::default(),
            None,
            "shared-principal".to_string(),
            "key-a".to_string(),
            Some("tenant-a".to_string()),
        );
        tenant_a.idempotency_key = Some("same-request".to_string());
        tenant_a.request_fingerprint = Some("fingerprint".to_string());
        let first_id = queue.enqueue(tenant_a.clone()).await.unwrap();

        let replay_id = queue.enqueue(tenant_a).await.unwrap();
        assert_eq!(replay_id, first_id);

        let mut tenant_b = ScanJob::new_owned(
            "example.com:443".to_string(),
            Default::default(),
            None,
            "shared-principal".to_string(),
            "key-b".to_string(),
            Some("tenant-b".to_string()),
        );
        tenant_b.idempotency_key = Some("same-request".to_string());
        tenant_b.request_fingerprint = Some("fingerprint".to_string());
        let second_id = queue.enqueue(tenant_b).await.unwrap();
        assert_ne!(second_id, first_id);

        let persisted = queue.get_job(&second_id).await.unwrap().unwrap();
        assert_eq!(persisted.tenant_id.as_deref(), Some("tenant-b"));
    }

    #[tokio::test]
    async fn sqlite_database_queue_rejects_jobs_when_at_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            DatabasePool::new(&DatabaseConfig::sqlite(directory.path().join("jobs.db")))
                .await
                .unwrap(),
        );
        let queue = DatabaseJobQueue::new(pool, 1, None);
        queue
            .enqueue(ScanJob::new(
                "first.example:443".to_string(),
                Default::default(),
                None,
            ))
            .await
            .unwrap();

        let error = queue
            .enqueue(ScanJob::new(
                "second.example:443".to_string(),
                Default::default(),
                None,
            ))
            .await
            .expect_err("the configured capacity should be enforced");

        assert!(matches!(error, crate::TlsError::Other(message) if message == "Job queue is full"));
    }
}
