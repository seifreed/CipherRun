//! Production-shaped API state tests using the durable database queue.

use std::sync::Arc;

use chrono::{Duration, Utc};
use cipherrun::api::contract::JobBackend;
use cipherrun::api::{ApiConfig, ApiServer};
use cipherrun::api::jobs::{RetryDisposition, ScanJob};
use cipherrun::db::{DatabaseConfig, DatabasePool};

async fn sqlite_pool(path: &std::path::Path) -> Arc<DatabasePool> {
    Arc::new(
        DatabasePool::new(&DatabaseConfig::sqlite(path.to_path_buf()))
            .await
            .expect("SQLite database should open"),
    )
}

fn production_config() -> ApiConfig {
    ApiConfig {
        job_backend: JobBackend::Database,
        local_executor: false,
        job_queue_capacity: 32,
        ..Default::default()
    }
}

#[tokio::test]
async fn production_server_restart_recovery_retry_dead_letter_cancel_and_tenant_traceability() {
    let directory = tempfile::tempdir().expect("temporary directory should exist");
    let database_path = directory.path().join("production-server.db");

    let (recoverable_id, dead_letter_id, cancelled_id, tenant_b_id) = {
        let pool = sqlite_pool(&database_path).await;
        let server = ApiServer::with_db_pool(production_config(), Some(pool.clone()))
            .expect("database-backed server should build");
        let queue = &server.state().job_queue;

        let mut recoverable = ScanJob::new_owned(
            "tenant-a.example:443".to_string(),
            Default::default(),
            None,
            "shared-principal".to_string(),
            "key-a".to_string(),
            Some("tenant-a".to_string()),
        );
        recoverable.idempotency_key = Some("same-request".to_string());
        recoverable.request_fingerprint = Some("fingerprint-a".to_string());
        let recoverable_id = queue
            .enqueue(recoverable)
            .await
            .expect("recoverable job should enqueue");
        let claimed = queue
            .dequeue()
            .await
            .expect("job should dequeue")
            .expect("recoverable job should be claimed");
        assert_eq!(claimed.status, cipherrun::api::models::response::ScanStatus::Running);
        assert_eq!(claimed.tenant_id.as_deref(), Some("tenant-a"));

        let mut dead_letter = ScanJob::new_owned(
            "dead-letter.example:443".to_string(),
            Default::default(),
            None,
            "shared-principal".to_string(),
            "key-a".to_string(),
            Some("tenant-a".to_string()),
        );
        dead_letter.request_fingerprint = Some("dead-letter-fingerprint".to_string());
        let dead_letter_id = queue
            .enqueue(dead_letter)
            .await
            .expect("dead-letter job should enqueue");
        let running_dead_letter = queue
            .dequeue()
            .await
            .expect("dead-letter job should dequeue")
            .expect("dead-letter job should be claimed");
        assert_eq!(
            queue
                .retry_or_dead_letter(&running_dead_letter, "permanent failure", 1)
                .await
                .expect("dead-letter transition should succeed"),
            RetryDisposition::DeadLettered
        );

        let cancelled = ScanJob::new_owned(
            "cancel.example:443".to_string(),
            Default::default(),
            None,
            "shared-principal".to_string(),
            "key-a".to_string(),
            Some("tenant-a".to_string()),
        );
        let cancelled_id = queue
            .enqueue(cancelled)
            .await
            .expect("cancelled job should enqueue");
        assert!(queue
            .cancel_job(&cancelled_id)
            .await
            .expect("cancellation should persist"));

        let mut tenant_b = ScanJob::new_owned(
            "tenant-b.example:443".to_string(),
            Default::default(),
            None,
            "shared-principal".to_string(),
            "key-b".to_string(),
            Some("tenant-b".to_string()),
        );
        tenant_b.idempotency_key = Some("same-request".to_string());
        tenant_b.request_fingerprint = Some("fingerprint-a".to_string());
        let tenant_b_id = queue
            .enqueue(tenant_b)
            .await
            .expect("same idempotency key must be isolated by tenant");
        assert_ne!(tenant_b_id, recoverable_id);

        if let DatabasePool::Sqlite(sqlite) = pool.as_ref() {
            sqlx::query("UPDATE cipherrun_jobs SET lease_until = ? WHERE id = ?")
                .bind(Utc::now() - Duration::minutes(5))
                .bind(&recoverable_id)
                .execute(sqlite)
                .await
                .expect("lease should be expired for recovery");
        }

        (recoverable_id, dead_letter_id, cancelled_id, tenant_b_id)
    };

    let pool = sqlite_pool(&database_path).await;
    let restarted = ApiServer::with_db_pool(production_config(), Some(pool))
        .expect("server should reconstruct after restart");
    let queue = &restarted.state().job_queue;

    let recovered = queue
        .get_job(&recoverable_id)
        .await
        .expect("recovered job should load")
        .expect("recovered job should remain persisted");
    assert_eq!(
        recovered.status,
        cipherrun::api::models::response::ScanStatus::Queued
    );
    assert_eq!(recovered.tenant_id.as_deref(), Some("tenant-a"));

    let dead_letter = queue
        .get_job(&dead_letter_id)
        .await
        .expect("dead-letter job should load")
        .expect("dead-letter job should remain persisted");
    assert!(dead_letter.dead_letter);
    assert_eq!(
        dead_letter.status,
        cipherrun::api::models::response::ScanStatus::Failed
    );

    let cancelled = queue
        .get_job(&cancelled_id)
        .await
        .expect("cancelled job should load")
        .expect("cancelled job should remain persisted");
    assert_eq!(
        cancelled.status,
        cipherrun::api::models::response::ScanStatus::Cancelled
    );
    let mut completed_copy = cancelled.clone();
    completed_copy.mark_completed(Default::default());
    assert!(!queue
        .update_job_preserving_cancelled(&completed_copy)
        .await
        .expect("cancelled update race should be handled"));

    let tenant_b = queue
        .get_job(&tenant_b_id)
        .await
        .expect("tenant-b job should load")
        .expect("tenant-b job should remain persisted");
    assert_eq!(tenant_b.tenant_id.as_deref(), Some("tenant-b"));
    assert_eq!(tenant_b.principal_id, "shared-principal");
}
