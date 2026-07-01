// Job Storage - Persistence layer for jobs

use crate::api::jobs::ScanJob;
use crate::api::models::response::ScanStatus;
use crate::Result;
use uuid::Uuid;

const MAX_JOB_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Job storage trait for persisting jobs
pub trait JobStorage: Send + Sync {
    /// Save job to storage
    fn save_job(&self, job: &ScanJob) -> Result<()>;

    /// Load job from storage
    fn load_job(&self, id: &str) -> Result<Option<ScanJob>>;

    /// Load all jobs
    fn load_all_jobs(&self) -> Result<Vec<ScanJob>>;

    /// Delete job
    fn delete_job(&self, id: &str) -> Result<()>;
}

/// File-based job storage (simple implementation)
pub struct FileJobStorage {
    base_path: std::path::PathBuf,
}

impl FileJobStorage {
    /// Create new file-based storage
    pub fn new(base_path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let base_path = base_path.into();
        std::fs::create_dir_all(&base_path)?;

        Ok(Self { base_path })
    }

    /// Get path for job file
    fn job_path(&self, id: &str) -> Result<std::path::PathBuf> {
        let uuid = Uuid::parse_str(id).map_err(|_| crate::TlsError::InvalidInput {
            message: format!("Invalid job id: {id}"),
        })?;
        if uuid.to_string() != id {
            return Err(crate::TlsError::InvalidInput {
                message: format!("Invalid job id: {id}"),
            });
        }
        if id.contains(std::path::MAIN_SEPARATOR) {
            return Err(crate::TlsError::InvalidInput {
                message: format!("Invalid job id: {id}"),
            });
        }
        Ok(self.base_path.join(format!("{}.json", id)))
    }

    fn read_job_file(path: &std::path::Path) -> Result<String> {
        let size = std::fs::metadata(path)?.len();
        if size > MAX_JOB_FILE_BYTES {
            return Err(crate::TlsError::InvalidInput {
                message: format!(
                    "Job file {} is too large: {} bytes (max {})",
                    path.display(),
                    size,
                    MAX_JOB_FILE_BYTES
                ),
            });
        }

        Ok(std::fs::read_to_string(path)?)
    }

    fn validate_loaded_job(expected_id: &str, job: &ScanJob) -> Result<()> {
        if job.id != expected_id {
            return Err(crate::TlsError::ParseError {
                message: format!(
                    "Persisted job id mismatch: file is {expected_id}, payload is {}",
                    job.id
                ),
            });
        }
        if job.progress > 100 {
            return Err(crate::TlsError::ParseError {
                message: format!("Persisted job progress is out of range: {}", job.progress),
            });
        }
        if matches!(
            job.status,
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
        ) && job.completed_at.is_none()
        {
            return Err(crate::TlsError::ParseError {
                message: "Persisted terminal job is missing completed_at".to_string(),
            });
        }
        if matches!(job.status, ScanStatus::Completed) && job.results.is_none() {
            return Err(crate::TlsError::ParseError {
                message: "Persisted completed job is missing results".to_string(),
            });
        }
        if matches!(job.status, ScanStatus::Failed)
            && job.error.as_deref().is_none_or(str::is_empty)
        {
            return Err(crate::TlsError::ParseError {
                message: "Persisted failed job is missing error".to_string(),
            });
        }
        Ok(())
    }
}

impl JobStorage for FileJobStorage {
    fn save_job(&self, job: &ScanJob) -> Result<()> {
        let path = self.job_path(&job.id)?;
        Self::validate_loaded_job(&job.id, job)?;
        let json = serde_json::to_string_pretty(job)?;
        if json.len() as u64 > MAX_JOB_FILE_BYTES {
            return Err(crate::TlsError::InvalidInput {
                message: format!(
                    "Job {} is too large to persist: {} bytes (max {})",
                    job.id,
                    json.len(),
                    MAX_JOB_FILE_BYTES
                ),
            });
        }
        std::fs::write(path, json)?;
        Ok(())
    }

    fn load_job(&self, id: &str) -> Result<Option<ScanJob>> {
        let path = self.job_path(id)?;

        if !path.exists() {
            return Ok(None);
        }

        let json = Self::read_job_file(&path)?;
        let job: ScanJob = serde_json::from_str(&json)?;
        Self::validate_loaded_job(id, &job)?;
        Ok(Some(job))
    }

    fn load_all_jobs(&self) -> Result<Vec<ScanJob>> {
        let mut jobs = Vec::new();

        for entry in std::fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let expected_id =
                    path.file_stem()
                        .and_then(|stem| stem.to_str())
                        .ok_or_else(|| crate::TlsError::InvalidInput {
                            message: format!("Invalid job file name: {}", path.display()),
                        })?;
                self.job_path(expected_id)?;
                let json = Self::read_job_file(&path)?;
                let job = serde_json::from_str::<ScanJob>(&json).map_err(|e| {
                    crate::TlsError::ParseError {
                        message: format!("Failed to parse job file {}: {}", path.display(), e),
                    }
                })?;
                Self::validate_loaded_job(expected_id, &job)?;
                jobs.push(job);
            }
        }

        Ok(jobs)
    }

    fn delete_job(&self, id: &str) -> Result<()> {
        let path = self.job_path(id)?;

        if path.exists() {
            std::fs::remove_file(path)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::{request::ScanOptions, response::ScanStatus};
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn test_file_storage() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");

        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);

        // Save
        storage
            .save_job(&job)
            .expect("test assertion should succeed");

        // Load
        let loaded = storage
            .load_job(&job.id)
            .unwrap()
            .expect("test assertion should succeed");
        assert_eq!(loaded.id, job.id);
        assert_eq!(loaded.target, job.target);

        // Delete
        storage
            .delete_job(&job.id)
            .expect("test assertion should succeed");
        assert!(storage.load_job(&job.id).unwrap().is_none());
    }

    #[test]
    fn test_load_all_jobs_reports_corrupt_job_file() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let job_id = Uuid::new_v4().to_string();
        std::fs::write(temp_dir.path().join(format!("{job_id}.json")), "{not-json")
            .expect("test assertion should succeed");

        let err = storage
            .load_all_jobs()
            .expect_err("corrupt persisted job should fail loudly");

        assert!(err.to_string().contains("Failed to parse job file"));
    }

    #[test]
    fn test_load_job_rejects_oversized_file_before_read() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let job_id = Uuid::new_v4().to_string();
        let path = temp_dir.path().join(format!("{job_id}.json"));
        let file = File::create(&path).expect("test assertion should succeed");
        file.set_len(MAX_JOB_FILE_BYTES + 1)
            .expect("test assertion should succeed");

        let err = storage
            .load_job(&job_id)
            .expect_err("oversized persisted job should fail before reading");

        assert!(err.to_string().contains("Job file"));
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn test_load_all_jobs_rejects_oversized_file_before_read() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let job_id = Uuid::new_v4().to_string();
        let path = temp_dir.path().join(format!("{job_id}.json"));
        let file = File::create(&path).expect("test assertion should succeed");
        file.set_len(MAX_JOB_FILE_BYTES + 1)
            .expect("test assertion should succeed");

        let err = storage
            .load_all_jobs()
            .expect_err("oversized persisted job should fail before reading");

        assert!(err.to_string().contains("Job file"));
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn test_save_job_rejects_oversized_serialized_job() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.status = ScanStatus::Failed;
        job.completed_at = Some(chrono::Utc::now());
        job.error = Some("x".repeat(MAX_JOB_FILE_BYTES as usize));

        let err = storage
            .save_job(&job)
            .expect_err("oversized serialized job should not be written");

        assert!(err.to_string().contains("too large to persist"));
        assert!(!temp_dir.path().join(format!("{}.json", job.id)).exists());
    }

    #[test]
    fn test_load_job_rejects_payload_id_mismatch() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        let file_id = job.id.clone();
        job.id = Uuid::new_v4().to_string();

        let json = serde_json::to_string(&job).expect("test assertion should succeed");
        std::fs::write(temp_dir.path().join(format!("{file_id}.json")), json)
            .expect("test assertion should succeed");

        let err = storage
            .load_job(&file_id)
            .expect_err("mismatched persisted id should fail");

        assert!(err.to_string().contains("Persisted job id mismatch"));
    }

    #[test]
    fn test_load_job_rejects_out_of_range_progress() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.progress = 101;

        let json = serde_json::to_string(&job).expect("test assertion should succeed");
        std::fs::write(temp_dir.path().join(format!("{}.json", job.id)), json)
            .expect("test assertion should succeed");

        let err = storage
            .load_job(&job.id)
            .expect_err("out-of-range persisted progress should fail");

        assert!(err.to_string().contains("progress is out of range"));
    }

    #[test]
    fn test_load_job_rejects_completed_job_without_results() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.status = ScanStatus::Completed;
        job.progress = 100;
        job.completed_at = Some(chrono::Utc::now());

        let json = serde_json::to_string(&job).expect("test assertion should succeed");
        std::fs::write(temp_dir.path().join(format!("{}.json", job.id)), json)
            .expect("test assertion should succeed");

        let err = storage
            .load_job(&job.id)
            .expect_err("completed job without results should fail");

        assert!(err.to_string().contains("missing results"));
    }

    #[test]
    fn test_load_job_rejects_failed_job_without_error() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.status = ScanStatus::Failed;
        job.completed_at = Some(chrono::Utc::now());

        let json = serde_json::to_string(&job).expect("test assertion should succeed");
        std::fs::write(temp_dir.path().join(format!("{}.json", job.id)), json)
            .expect("test assertion should succeed");

        let err = storage
            .load_job(&job.id)
            .expect_err("failed job without error should fail");

        assert!(err.to_string().contains("missing error"));
    }

    #[test]
    fn test_load_job_rejects_terminal_job_without_completed_at() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.status = ScanStatus::Cancelled;

        let json = serde_json::to_string(&job).expect("test assertion should succeed");
        std::fs::write(temp_dir.path().join(format!("{}.json", job.id)), json)
            .expect("test assertion should succeed");

        let err = storage
            .load_job(&job.id)
            .expect_err("terminal job without completed_at should fail");

        assert!(err.to_string().contains("missing completed_at"));
    }

    #[test]
    fn test_save_job_rejects_unloadable_terminal_job() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.status = ScanStatus::Completed;
        job.progress = 100;
        job.completed_at = Some(chrono::Utc::now());

        let err = storage
            .save_job(&job)
            .expect_err("storage should reject jobs it cannot load back");

        assert!(err.to_string().contains("missing results"));
        assert!(!temp_dir.path().join(format!("{}.json", job.id)).exists());
    }

    #[test]
    fn test_load_all_jobs_rejects_invalid_or_mismatched_file_ids() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");
        let job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        let json = serde_json::to_string(&job).expect("test assertion should succeed");
        std::fs::write(temp_dir.path().join("not-a-job-id.json"), json)
            .expect("test assertion should succeed");

        let err = storage
            .load_all_jobs()
            .expect_err("invalid persisted file id should fail");

        assert!(err.to_string().contains("Invalid job id"));
    }

    #[test]
    fn test_file_storage_rejects_invalid_job_ids() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let storage = FileJobStorage::new(temp_dir.path()).expect("test assertion should succeed");

        let mut job = ScanJob::new("example.com:443".to_string(), ScanOptions::default(), None);
        job.id = "../outside".to_string();

        assert!(storage.save_job(&job).is_err());
        assert!(storage.load_job("../outside").is_err());
        assert!(storage.delete_job("../outside").is_err());
        assert!(storage
            .load_job("550E8400-E29B-41D4-A716-446655440000")
            .is_err());
        assert!(!temp_dir.path().join("../outside.json").exists());
    }
}
