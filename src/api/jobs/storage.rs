// Job Storage - Persistence layer for jobs

use crate::api::jobs::ScanJob;
use anyhow::Result;

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
    fn job_path(&self, id: &str) -> std::path::PathBuf {
        self.base_path.join(format!("{}.json", id))
    }
}

impl JobStorage for FileJobStorage {
    fn save_job(&self, job: &ScanJob) -> Result<()> {
        let path = self.job_path(&job.id);
        let json = serde_json::to_string_pretty(job)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn load_job(&self, id: &str) -> Result<Option<ScanJob>> {
        let path = self.job_path(id);

        if !path.exists() {
            return Ok(None);
        }

        let json = std::fs::read_to_string(path)?;
        let job: ScanJob = serde_json::from_str(&json)?;
        Ok(Some(job))
    }

    fn load_all_jobs(&self) -> Result<Vec<ScanJob>> {
        let mut jobs = Vec::new();

        for entry in std::fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let json = std::fs::read_to_string(&path)?;
                if let Ok(job) = serde_json::from_str::<ScanJob>(&json) {
                    jobs.push(job);
                }
            }
        }

        Ok(jobs)
    }

    fn delete_job(&self, id: &str) -> Result<()> {
        let path = self.job_path(id);

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
}
