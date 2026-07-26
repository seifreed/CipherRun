// CipherRun - A fast, modular, and scalable TLS/SSL security scanner
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

//! Path extension trait for convenient path-to-string conversion with typed errors.

use crate::Result;
use crate::error::TlsError;
use std::path::{Path, PathBuf};

/// Extension trait for converting paths to strings with proper error handling.
///
/// This trait eliminates the repetitive pattern of:
/// ```ignore
/// path.to_str().ok_or_else(|| TlsError::Other("Invalid file path".to_string()))?
/// ```
///
/// Instead, you can simply use:
/// ```ignore
/// path.to_str_checked()?
/// ```
pub trait PathExt {
    /// Converts the path to a string slice, returning a [`TlsError`] if the path
    /// contains invalid UTF-8 characters.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not valid UTF-8.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use cipherrun::utils::path_ext::PathExt;
    /// use std::path::Path;
    ///
    /// let path = Path::new("/some/valid/path");
    /// let path_str = path.to_str_checked()?;
    /// ```
    fn to_str_checked(&self) -> Result<&str>;
}

impl PathExt for Path {
    fn to_str_checked(&self) -> Result<&str> {
        self.to_str().ok_or_else(|| {
            TlsError::Other("Invalid file path: path contains invalid UTF-8".to_string())
        })
    }
}

impl PathExt for PathBuf {
    fn to_str_checked(&self) -> Result<&str> {
        self.as_path().to_str_checked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn test_to_str_checked_valid_paths() {
        for value in [
            "/some/valid/path",
            "/path/with spaces/file.txt",
            "relative/path.txt",
        ] {
            assert_eq!(Path::new(value).to_str_checked().unwrap(), value);
        }

        for value in ["/some/valid/path", "relative/path.txt"] {
            assert_eq!(PathBuf::from(value).to_str_checked().unwrap(), value);
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_path_to_str_checked_invalid_utf8() {
        let invalid = OsString::from_vec(vec![0xff, 0xfe, 0xfd]);
        let path = PathBuf::from(invalid);
        let err = path.to_str_checked().unwrap_err();
        assert!(err.to_string().contains("Invalid file path"));
    }
}
