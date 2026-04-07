use super::ValidationError;
use std::path::{Path, PathBuf};

/// Sanitize and validate filesystem path
///
/// # Security Requirements
/// - Prevents path traversal attacks (CWE-22)
/// - Canonicalizes path and verifies it's within allowed directory
/// - Rejects null bytes and other dangerous characters
/// - OWASP A01:2021 - Broken Access Control
pub fn sanitize_path(path: &str, base_dir: &Path) -> std::result::Result<PathBuf, ValidationError> {
    if path.contains('\0') {
        return Err(ValidationError::InvalidPath(
            "Path contains null byte".to_string(),
        ));
    }

    if path.starts_with('/') || path.starts_with('\\') {
        return Err(ValidationError::InvalidPath(
            "Absolute paths are not allowed".to_string(),
        ));
    }

    if path.contains("..") {
        return Err(ValidationError::InvalidPath(
            "Path traversal sequences (..) are not allowed".to_string(),
        ));
    }

    #[cfg(windows)]
    {
        if path.len() >= 2 && path.as_bytes()[1] == b':' {
            return Err(ValidationError::InvalidPath(
                "Drive letters are not allowed".to_string(),
            ));
        }
    }

    let full_path = base_dir.join(path);

    let canonical_base = base_dir.canonicalize().map_err(|e| {
        ValidationError::InvalidPath(format!("Cannot canonicalize base dir: {}", e))
    })?;

    let canonical_path = full_path.canonicalize().unwrap_or_else(|_| {
        if let Some(parent) = full_path.parent()
            && let Ok(canonical_parent) = parent.canonicalize()
            && let Some(filename) = full_path.file_name()
        {
            return canonical_parent.join(filename);
        }
        full_path.clone()
    });

    if !canonical_path.starts_with(&canonical_base) {
        return Err(ValidationError::InvalidPath(format!(
            "Path escapes base directory: {} not under {}",
            canonical_path.display(),
            canonical_base.display()
        )));
    }

    Ok(canonical_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_sanitize_path() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let base = temp_dir.path();

        let test_file = base.join("test.txt");
        fs::write(&test_file, "test").expect("test assertion should succeed");

        let subdir = base.join("subdir");
        fs::create_dir(&subdir).expect("test assertion should succeed");
        let nested_file = subdir.join("test.txt");
        fs::write(&nested_file, "test").expect("test assertion should succeed");

        assert!(sanitize_path("test.txt", base).is_ok());
        assert!(sanitize_path("subdir/test.txt", base).is_ok());

        assert!(sanitize_path("../etc/passwd", base).is_err());
        assert!(sanitize_path("../../etc/passwd", base).is_err());
        assert!(sanitize_path("./../etc/passwd", base).is_err());

        assert!(sanitize_path("/etc/passwd", base).is_err());
        assert!(sanitize_path("test\0.txt", base).is_err());
    }

    #[test]
    fn test_sanitize_path_allows_new_file_within_base() {
        let temp_dir = TempDir::new().expect("test assertion should succeed");
        let base = temp_dir.path();

        let safe_path = sanitize_path("newfile.txt", base).expect("test assertion should succeed");
        assert!(safe_path.file_name().is_some());

        fs::write(&safe_path, "test content").expect("Should be able to write to safe path");
        assert!(safe_path.exists(), "File should have been created");

        let _ = fs::remove_file(&safe_path);
    }
}
