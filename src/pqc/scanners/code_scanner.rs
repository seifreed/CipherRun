use crate::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::LazyLock;

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

/// (display_pattern, compiled_regex, algorithm_name, severity)
/// Patterns that refer to algorithm names (RC4, MD5, SHA1, DES) use `\b` word
/// boundaries to avoid matching substrings like `SHA128`, `ADES`, or `rc4_legacy_ok`.
/// API-shaped patterns (e.g. `RSA.new`, `crypto.createECDH`) keep literal matching.
struct PqcCodePattern {
    display: &'static str,
    regex: Regex,
    algorithm: &'static str,
    severity: &'static str,
}

static PATTERNS: LazyLock<Vec<PqcCodePattern>> = LazyLock::new(|| {
    let mk = |display: &'static str, re: &str, algorithm: &'static str, severity: &'static str| {
        PqcCodePattern {
            display,
            regex: Regex::new(re).expect("valid pattern regex"),
            algorithm,
            severity,
        }
    };
    vec![
        mk("RSA.new", r"RSA\.new\b", "RSA", "High"),
        mk(
            "KeyPairGenerator.getInstance(\"RSA\")",
            r#"KeyPairGenerator\.getInstance\(\s*"RSA""#,
            "RSA",
            "High",
        ),
        mk("crypto.createECDH", r"crypto\.createECDH\b", "ECDH (classical)", "High"),
        mk("EC_KEY_new", r"\bEC_KEY_new\b", "ECDH (OpenSSL C)", "High"),
        mk("DH_new", r"\bDH_new\b", "DH (classical)", "High"),
        mk(
            "Cipher.getInstance(\"DES",
            r#"Cipher\.getInstance\(\s*"DES"#,
            "DES",
            "High",
        ),
        mk(
            "createCipheriv(\"des",
            r#"createCipheriv\(\s*"des"#,
            "DES",
            "High",
        ),
        mk("RC4", r"(?i)\bRC4\b", "RC4", "High"),
        mk("MD5", r"(?i)\bMD5\b", "MD5", "Medium"),
        mk("SHA1", r"(?i)\bSHA-?1\b", "SHA-1", "Medium"),
        mk("DES", r"(?i)\bDES\b", "DES", "High"),
    ]
});

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
        for pat in PATTERNS.iter() {
            if pat.regex.is_match(line) {
                findings.push(CodeFinding {
                    file: path.display().to_string(),
                    line: line_no + 1,
                    pattern: pat.display.to_string(),
                    algorithm: pat.algorithm.to_string(),
                    severity: pat.severity.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn algorithms_matched(line: &str) -> Vec<&'static str> {
        PATTERNS
            .iter()
            .filter(|p| p.regex.is_match(line))
            .map(|p| p.algorithm)
            .collect()
    }

    #[test]
    fn test_code_scanner_flags_sha1_with_word_boundary() {
        let matches = algorithms_matched("let hasher = SHA1::new();");
        assert!(
            matches.contains(&"SHA-1"),
            "SHA1 at word boundary must be detected; got {:?}",
            matches
        );
    }

    #[test]
    fn test_code_scanner_ignores_sha128_and_sha256() {
        // SHA128 is not a real algorithm but is a valid identifier — previous
        // substring check would falsely flag it via "SHA1".
        let matches = algorithms_matched("let digest = SHA128_digest_len;");
        assert!(
            !matches.contains(&"SHA-1"),
            "SHA128 must not match SHA-1 pattern; got {:?}",
            matches
        );
        // SHA256 must also not match the SHA-1 pattern.
        let matches = algorithms_matched("use sha256::Digest;");
        assert!(
            !matches.contains(&"SHA-1"),
            "SHA256 must not match SHA-1; got {:?}",
            matches
        );
    }

    #[test]
    fn test_code_scanner_ignores_rc4_substring_in_identifier() {
        // "HERC4" or "rc4_legacy_compat" would have matched the old substring check.
        let matches = algorithms_matched("let herc4_value = 0;");
        assert!(
            !matches.contains(&"RC4"),
            "RC4 inside identifier must not match; got {:?}",
            matches
        );
    }

    #[test]
    fn test_code_scanner_flags_rc4_standalone() {
        let matches = algorithms_matched("cipher = RC4();");
        assert!(matches.contains(&"RC4"));
    }

    #[test]
    fn test_code_scanner_flags_md5_variants() {
        assert!(algorithms_matched("hashlib.md5(data)").contains(&"MD5"));
        assert!(!algorithms_matched("let md512_ok = 0;").contains(&"MD5"));
    }

    #[test]
    fn test_code_scanner_flags_sha_hyphen_one() {
        assert!(algorithms_matched("Signature alg: SHA-1").contains(&"SHA-1"));
    }
}
