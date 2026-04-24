// SSH Config PQC Scanner — parses sshd_config for quantum-vulnerable algorithms

use crate::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshScanResult {
    pub path: String,
    pub quantum_vulnerable: Vec<String>,
    pub pqc_safe: Vec<String>,
    pub score: u8,
    pub recommendations: Vec<String>,
}

pub struct SshScanner;

impl SshScanner {
    pub fn scan(path: &Path) -> Result<SshScanResult> {
        let content = std::fs::read_to_string(path)?;
        let mut vulnerable = Vec::new();
        let mut safe = Vec::new();
        let mut recommendations = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            let directive = trimmed.split_whitespace().next().unwrap_or_default();

            // Classical KEX algorithms (quantum-vulnerable)
            if directive.eq_ignore_ascii_case("kexalgorithms") {
                for alg in extract_algorithms(trimmed) {
                    let Some(alg) = enabled_algorithm(&alg) else {
                        continue;
                    };
                    if is_ssh_pqc_kex(&alg) {
                        safe.push(alg);
                    } else {
                        vulnerable.push(alg);
                    }
                }
            }

            // Host key types
            if directive.eq_ignore_ascii_case("hostkeyalgorithms")
                || directive.eq_ignore_ascii_case("pubkeyacceptedalgorithms")
            {
                for alg in extract_algorithms(trimmed) {
                    let Some(alg) = enabled_algorithm(&alg) else {
                        continue;
                    };
                    if is_ssh_pqc_hostkey(&alg) {
                        safe.push(alg);
                    } else if is_ssh_classical_ecdsa(&alg) || alg.contains("rsa") {
                        vulnerable.push(alg);
                    }
                }
            }
        }

        if safe.is_empty() {
            recommendations.push(
                "Add mlkem768nistp256-sha256@openssh.com or sntrup761x25519-sha512@openssh.com to KexAlgorithms.".to_string(),
            );
        } else if !vulnerable.is_empty() {
            recommendations.push(format!(
                "Remove classical-only algorithms ({}) from KexAlgorithms/HostKeyAlgorithms to complete the PQC transition.",
                vulnerable.join(", ")
            ));
        }

        let score = if safe.is_empty() {
            0u8
        } else if vulnerable.is_empty() {
            100
        } else {
            50
        };

        Ok(SshScanResult {
            path: path.display().to_string(),
            quantum_vulnerable: vulnerable,
            pqc_safe: safe,
            score,
            recommendations,
        })
    }
}

fn extract_algorithms(line: &str) -> Vec<String> {
    line.split_once(char::is_whitespace)
        .map(|x| x.1)
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn enabled_algorithm(alg: &str) -> Option<String> {
    let alg = alg.trim();
    if alg.starts_with('-') {
        return None;
    }

    Some(alg.trim_start_matches(['+', '^']).to_string())
}

fn is_ssh_pqc_kex(alg: &str) -> bool {
    let lower = alg.to_lowercase();
    lower.contains("mlkem") || lower.contains("sntrup") || lower.contains("kyber")
}

fn is_ssh_pqc_hostkey(alg: &str) -> bool {
    let lower = alg.to_lowercase();
    lower.contains("dilithium") || lower.contains("falcon") || lower.contains("mldsa")
}

fn is_ssh_classical_ecdsa(alg: &str) -> bool {
    let lower = alg.to_lowercase();
    lower.contains("ecdsa") && !is_ssh_pqc_hostkey(alg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_algorithms() {
        let algs = extract_algorithms("KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256");
        assert_eq!(algs, vec!["curve25519-sha256", "ecdh-sha2-nistp256"]);
    }

    #[test]
    fn test_pqc_kex_detection() {
        assert!(is_ssh_pqc_kex("mlkem768nistp256-sha256@openssh.com"));
        assert!(is_ssh_pqc_kex("sntrup761x25519-sha512@openssh.com"));
        assert!(!is_ssh_pqc_kex("curve25519-sha256"));
    }

    #[test]
    fn test_ssh_mixed_config_generates_removal_recommendation() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        writeln!(
            f,
            "KexAlgorithms mlkem768nistp256-sha256@openssh.com,curve25519-sha256,ecdh-sha2-nistp256"
        )
        .expect("write config");

        let result = SshScanner::scan(f.path()).expect("scan should succeed");
        assert_eq!(result.score, 50, "mixed config must score 50");
        assert!(
            !result.pqc_safe.is_empty() && !result.quantum_vulnerable.is_empty(),
            "mixed config should populate both safe and vulnerable lists"
        );
        assert!(
            result
                .recommendations
                .iter()
                .any(|r| r.contains("Remove") && r.contains("curve25519-sha256")),
            "mixed config must emit an actionable removal recommendation; got {:?}",
            result.recommendations
        );
    }

    #[test]
    fn test_ssh_ignores_directives_that_only_share_a_prefix() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        writeln!(
            f,
            "KexAlgorithmsExtra curve25519-sha256\nHostKeyAlgorithmsExtra ssh-rsa"
        )
        .expect("write config");

        let result = SshScanner::scan(f.path()).expect("scan should succeed");

        assert!(
            result.quantum_vulnerable.is_empty(),
            "unknown directives must not be parsed as real SSH crypto directives; got {:?}",
            result.quantum_vulnerable
        );
        assert!(result.pqc_safe.is_empty());
    }

    #[test]
    fn test_ssh_removal_modifiers_do_not_count_as_enabled_algorithms() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        writeln!(
            f,
            "KexAlgorithms -diffie-hellman-group14-sha1\nHostKeyAlgorithms -ssh-rsa"
        )
        .expect("write config");

        let result = SshScanner::scan(f.path()).expect("scan should succeed");

        assert!(
            result.quantum_vulnerable.is_empty(),
            "removed algorithms must not be counted as enabled vulnerabilities; got {:?}",
            result.quantum_vulnerable
        );
    }
}
