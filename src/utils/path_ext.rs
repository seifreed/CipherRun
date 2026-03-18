// CipherRun - A fast, modular, and scalable TLS/SSL security scanner
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

//! Path extension trait for convenient path-to-string conversion with anyhow errors.

use anyhow::{Result, anyhow};
use std::path::{Path, PathBuf};

/// Extension trait for converting paths to strings with proper error handling.
///
/// This trait eliminates the repetitive pattern of:
/// ```ignore
/// path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid file path"))?
/// ```
///
/// Instead, you can simply use:
/// ```ignore
/// path.to_str_anyhow()?
/// ```
pub trait PathExt {
    /// Converts the path to a string slice, returning an anyhow error if the path
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
    /// let path_str = path.to_str_anyhow()?;
    /// ```
    fn to_str_anyhow(&self) -> Result<&str>;
}

impl PathExt for Path {
    fn to_str_anyhow(&self) -> Result<&str> {
        self.to_str()
            .ok_or_else(|| anyhow!("Invalid file path: path contains invalid UTF-8"))
    }
}

impl PathExt for PathBuf {
    fn to_str_anyhow(&self) -> Result<&str> {
        self.to_str()
            .ok_or_else(|| anyhow!("Invalid file path: path contains invalid UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn test_path_to_str_anyhow_valid() {
        let path = Path::new("/some/valid/path");
        assert_eq!(path.to_str_anyhow().unwrap(), "/some/valid/path");
    }

    #[test]
    fn test_pathbuf_to_str_anyhow_valid() {
        let path = PathBuf::from("/some/valid/path");
        assert_eq!(path.to_str_anyhow().unwrap(), "/some/valid/path");
    }

    #[test]
    fn test_path_with_spaces() {
        let path = Path::new("/path/with spaces/file.txt");
        assert_eq!(path.to_str_anyhow().unwrap(), "/path/with spaces/file.txt");
    }

    #[test]
    fn test_relative_path_to_str_anyhow() {
        let path = Path::new("relative/path.txt");
        assert_eq!(path.to_str_anyhow().unwrap(), "relative/path.txt");
    }

    #[test]
    fn test_pathbuf_relative_to_str_anyhow() {
        let path = PathBuf::from("relative/path.txt");
        assert_eq!(path.to_str_anyhow().unwrap(), "relative/path.txt");
    }

    #[cfg(unix)]
    #[test]
    fn test_path_to_str_anyhow_invalid_utf8() {
        let invalid = OsString::from_vec(vec![0xff, 0xfe, 0xfd]);
        let path = PathBuf::from(invalid);
        let err = path.to_str_anyhow().unwrap_err();
        assert!(err.to_string().contains("Invalid file path"));
    }
}
