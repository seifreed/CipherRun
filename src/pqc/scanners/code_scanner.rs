use crate::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFinding {
    pub file: String,
    pub line: usize,
    pub pattern: String,
    pub algorithm: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeScanResult {
    pub root: String,
    pub files_scanned: usize,
    pub findings: Vec<CodeFinding>,
}

/// (pattern_substring, algorithm_name, severity)
const PATTERNS: &[(&str, &str, &str)] = &[
    ("RSA.new", "RSA", "High"),
    ("KeyPairGenerator.getInstance(\"RSA\")", "RSA", "High"),
    ("crypto.createECDH", "ECDH (classical)", "High"),
    ("EC_KEY_new", "ECDH (OpenSSL C)", "High"),
    ("DH_new", "DH (classical)", "High"),
    ("Cipher.getInstance(\"DES", "DES", "High"),
    ("createCipheriv(\"des", "DES", "High"),
    ("RC4", "RC4", "High"),
    ("MD5", "MD5", "Medium"),
    ("SHA1", "SHA-1", "Medium"),
];

pub struct CodeScanner;

impl CodeScanner {
    pub fn scan(root: &Path) -> Result<CodeScanResult> {
        let mut findings = Vec::new();
        let mut files_scanned = 0;

        scan_dir(root, &mut findings, &mut files_scanned)?;

        Ok(CodeScanResult {
            root: root.display().to_string(),
            files_scanned,
            findings,
        })
    }
}

fn scan_dir(dir: &Path, findings: &mut Vec<CodeFinding>, count: &mut usize) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !matches!(name, "target" | ".git" | "node_modules" | "vendor") {
                scan_dir(&path, findings, count)?;
            }
        } else if is_source_file(&path) {
            scan_file(&path, findings)?;
            *count += 1;
        }
    }
    Ok(())
}

fn scan_file(path: &Path, findings: &mut Vec<CodeFinding>) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    for (line_no, line) in content.lines().enumerate() {
        for (pattern, algorithm, severity) in PATTERNS {
            if line.contains(pattern) {
                findings.push(CodeFinding {
                    file: path.display().to_string(),
                    line: line_no + 1,
                    pattern: pattern.to_string(),
                    algorithm: algorithm.to_string(),
                    severity: severity.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn is_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("rs" | "py" | "js" | "ts" | "go" | "java" | "c" | "cpp" | "h" | "cs" | "rb" | "php")
    )
}
