use crate::application::PolicySource;
use crate::policy::Policy;
use crate::policy::parser::{PolicyDocumentSource, PolicyLoader};
use std::path::Path;

pub struct FilesystemPolicySource;

impl PolicyDocumentSource for FilesystemPolicySource {
    fn read_to_string(&self, path: &Path) -> crate::Result<String> {
        std::fs::read_to_string(path).map_err(|source| crate::TlsError::IoError { source })
    }
}

impl PolicySource for FilesystemPolicySource {
    fn load_policy(&self, policy_path: &Path) -> crate::Result<Policy> {
        let base_path = policy_path.parent().unwrap_or_else(|| Path::new("."));
        PolicyLoader::from_source(base_path, self).load(policy_path)
    }
}
