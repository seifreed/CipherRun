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
            let lower = trimmed.to_lowercase();

            // Classical KEX algorithms (quantum-vulnerable)
            if lower.starts_with("kexalgorithms") {
                for alg in extract_algorithms(trimmed) {
                    if is_ssh_pqc_kex(&alg) {
                        safe.push(alg);
                    } else {
                        vulnerable.push(alg);
                    }
                }
            }

            // Host key types
            if lower.starts_with("hostkeyalgorithms") || lower.starts_with("pubkeyacceptedalgorithms") {
                for alg in extract_algorithms(trimmed) {
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
}
