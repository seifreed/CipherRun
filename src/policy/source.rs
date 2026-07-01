use crate::application::PolicySource;
use crate::policy::parser::{PolicyDocumentSource, PolicyLoader};
use crate::policy::Policy;
use std::path::Path;

const MAX_POLICY_FILE_BYTES: u64 = 1024 * 1024;

pub struct FilesystemPolicySource;

impl PolicyDocumentSource for FilesystemPolicySource {
    fn read_to_string(&self, path: &Path) -> crate::Result<String> {
        let size = std::fs::metadata(path)
            .map_err(|source| crate::TlsError::IoError { source })?
            .len();
        if size > MAX_POLICY_FILE_BYTES {
            return Err(crate::TlsError::ConfigError {
                message: format!(
                    "Policy file '{}' is too large: {} bytes (max {})",
                    path.display(),
                    size,
                    MAX_POLICY_FILE_BYTES
                ),
            });
        }

        std::fs::read_to_string(path).map_err(|source| crate::TlsError::IoError { source })
    }
}

impl PolicySource for FilesystemPolicySource {
    fn load_policy(&self, policy_path: &Path) -> crate::Result<Policy> {
        let base_path = policy_path.parent().unwrap_or_else(|| Path::new("."));
        PolicyLoader::from_source(base_path, self).load(policy_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn test_read_to_string_rejects_oversized_policy_before_read() {
        let temp_dir = tempfile::tempdir().expect("test assertion should succeed");
        let path = temp_dir.path().join("oversized-policy.yaml");
        let file = File::create(&path).expect("test assertion should succeed");
        file.set_len(MAX_POLICY_FILE_BYTES + 1)
            .expect("test assertion should succeed");

        let err = FilesystemPolicySource
            .read_to_string(&path)
            .expect_err("oversized policy should fail before reading");

        assert!(err.to_string().contains("Policy file"));
        assert!(err.to_string().contains("too large"));
    }
}
