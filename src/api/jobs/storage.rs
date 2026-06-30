// Job Storage - Persistence layer for jobs

use crate::Result;
use crate::api::jobs::ScanJob;
use uuid::Uuid;

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

    fn validate_loaded_job(expected_id: &str, job: &ScanJob) -> Result<()> {
        if job.id != expected_id {
            return Err(crate::TlsError::ParseError {
                message: format!(
                    "Persisted job id mismatch: file is {expected_id}, payload is {}",
                    job.id
                ),
            });
        }
        Ok(())
    }
}

impl JobStorage for FileJobStorage {
    fn save_job(&self, job: &ScanJob) -> Result<()> {
        let path = self.job_path(&job.id)?;
        let json = serde_json::to_string_pretty(job)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn load_job(&self, id: &str) -> Result<Option<ScanJob>> {
        let path = self.job_path(id)?;

        if !path.exists() {
            return Ok(None);
        }

        let json = std::fs::read_to_string(path)?;
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
                let expected_id = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .ok_or_else(|| crate::TlsError::InvalidInput {
                        message: format!("Invalid job file name: {}", path.display()),
                    })?;
                self.job_path(expected_id)?;
                let json = std::fs::read_to_string(&path)?;
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
    use crate::api::models::request::ScanOptions;
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
        assert!(storage.load_job("550E8400-E29B-41D4-A716-446655440000").is_err());
        assert!(!temp_dir.path().join("../outside.json").exists());
    }
}
