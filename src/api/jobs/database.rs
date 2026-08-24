use super::{JobQueue, ScanJob};
use crate::api::models::response::ScanStatus;
use crate::db::DatabasePool;
use crate::{Result, tls_bail};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sqlx::Row;
use std::sync::Arc;
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

    async fn ensure_schema(&self) -> Result<()> {
        let sqlite = format!(
            "CREATE TABLE IF NOT EXISTS {TABLE} (\
             id TEXT PRIMARY KEY, status TEXT NOT NULL, queued_at TIMESTAMP NOT NULL,\
             job_json TEXT NOT NULL, principal_id TEXT NOT NULL DEFAULT '',\
             idempotency_key TEXT, request_fingerprint TEXT, lease_until TIMESTAMP,\
             attempts INTEGER NOT NULL DEFAULT 0)"
        );
        let postgres = format!(
            "CREATE TABLE IF NOT EXISTS {TABLE} (\
             id TEXT PRIMARY KEY, status TEXT NOT NULL, queued_at TIMESTAMPTZ NOT NULL,\
             job_json TEXT NOT NULL, principal_id TEXT NOT NULL DEFAULT '',\
             idempotency_key TEXT, request_fingerprint TEXT, lease_until TIMESTAMPTZ,\
             attempts INTEGER NOT NULL DEFAULT 0)"
        );
        match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(&sqlite).execute(pool).await.map_err(db_error)?;
                sqlx::query(&format!(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_{TABLE}_idempotency \
                     ON {TABLE}(principal_id, idempotency_key)"
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
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_{TABLE}_idempotency \
                     ON {TABLE}(principal_id, idempotency_key)"
                ))
                .execute(pool)
                .await
                .map_err(db_error)?;
            }
        }
        self.recover_expired_leases().await
    }

    async fn recover_expired_leases(&self) -> Result<()> {
        let now = Utc::now();
        let query = format!(
            "UPDATE {TABLE} SET status = 'queued', lease_until = NULL \
             WHERE status = 'running' AND lease_until IS NOT NULL AND lease_until < {}",
            placeholder(self.pool.as_ref(), 1)
        );
        match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query(&query)
                .bind(now)
                .execute(pool)
                .await
                .map(|_| ()),
            DatabasePool::Postgres(pool) => sqlx::query(&query)
                .bind(now)
                .execute(pool)
                .await
                .map(|_| ()),
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
            match self.pool.as_ref() {
                DatabasePool::Sqlite(pool) => sqlx::query(&update)
                    .bind(json)
                    .bind(&id)
                    .execute(pool)
                    .await
                    .map(|_| ())
                    .map_err(db_error)?,
                DatabasePool::Postgres(pool) => sqlx::query(&update)
                    .bind(json)
                    .bind(&id)
                    .execute(pool)
                    .await
                    .map(|_| ())
                    .map_err(db_error)?,
            }
        }
        Ok(())
    }

    async fn active_count(&self) -> Result<i64> {
        let query = format!("SELECT COUNT(*) FROM {TABLE} WHERE status IN ('queued','running')");
        match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query_scalar(&query).fetch_one(pool).await,
            DatabasePool::Postgres(pool) => sqlx::query_scalar(&query).fetch_one(pool).await,
        }
        .map_err(db_error)
    }

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
    async fn enqueue(&self, job: ScanJob) -> Result<String> {
        self.ensure_schema().await?;
        if self.active_count().await? >= i64::try_from(self.max_capacity).unwrap_or(i64::MAX) {
            tls_bail!("Job queue is full");
        }
        if let Some(key) = job.idempotency_key.as_deref() {
            let query = format!(
                "SELECT id, request_fingerprint FROM {TABLE} WHERE principal_id = {} AND idempotency_key = {}",
                placeholder(self.pool.as_ref(), 1),
                placeholder(self.pool.as_ref(), 2)
            );
            let existing: Option<(String, Option<String>)> = match self.pool.as_ref() {
                DatabasePool::Sqlite(pool) => sqlx::query(&query)
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
            "INSERT INTO {TABLE} (id,status,queued_at,job_json,principal_id,idempotency_key,request_fingerprint,lease_until,attempts) \
             VALUES ({},{},{},{},{},{},{},NULL,0) ON CONFLICT DO NOTHING",
            placeholder(self.pool.as_ref(), 1),
            placeholder(self.pool.as_ref(), 2),
            placeholder(self.pool.as_ref(), 3),
            placeholder(self.pool.as_ref(), 4),
            placeholder(self.pool.as_ref(), 5),
            placeholder(self.pool.as_ref(), 6),
            placeholder(self.pool.as_ref(), 7)
        );
        let rows_affected = match self.pool.as_ref() {
            DatabasePool::Sqlite(pool) => sqlx::query(&query)
                .bind(&job.id)
                .bind(status_name(job.status))
                .bind(job.queued_at)
                .bind(json)
                .bind(&job.principal_id)
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

    async fn get_job(&self, id: &str) -> Result<Option<ScanJob>> {
        self.ensure_schema().await?;
        self.load(id).await
    }

    async fn update_job(&self, job: &ScanJob) -> Result<()> {
        self.ensure_schema().await?;
        let lease = if matches!(job.status, ScanStatus::Running) {
            Some(Utc::now() + Duration::seconds(LEASE_SECONDS))
        } else {
            None
        };
        self.update_row(job, lease).await
    }

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

    async fn active_jobs_count(&self) -> Result<usize> {
        self.ensure_schema().await?;
        let count = self.active_count().await?;
        usize::try_from(count)
            .map_err(|_| crate::TlsError::DatabaseError("Invalid active count".to_string()))
    }

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
        let recovered_job = recovered.get_job(&id).await.unwrap().unwrap();
        assert_eq!(recovered_job.status, ScanStatus::Queued);
        assert!(recovered_job.started_at.is_none());
    }
}
