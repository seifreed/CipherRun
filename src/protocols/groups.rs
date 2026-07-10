// Key Exchange Groups Enumeration (Curves, DH groups, PQ groups)

use crate::Result;
use crate::utils::network::Target;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use serde::{Deserialize, Serialize};
use tokio::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupType {
    EllipticCurve,
    FiniteField,
    PostQuantum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeGroup {
    pub name: String,
    pub iana_value: u16,
    pub group_type: GroupType,
    pub bits: u16,
    pub supported: bool,
    /// True for classical groups (ECDH, DHE, finite-field) — broken by Shor's algorithm
    pub quantum_vulnerable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupEnumerationResult {
    pub groups: Vec<KeyExchangeGroup>,
    pub measured: bool,
    pub details: String,
}

/// Static description of a key exchange group and the OpenSSL groups-list name
/// used to offer it during a probe.
struct GroupSpec {
    name: &'static str,
    openssl_name: &'static str,
    iana_value: u16,
    group_type: GroupType,
    bits: u16,
    quantum_vulnerable: bool,
}

/// Key exchange groups probed during enumeration, in offer order.
const GROUP_SPECS: &[GroupSpec] = &[
    // Elliptic curves — quantum-vulnerable (Shor's algorithm).
    GroupSpec {
        name: "secp256r1 (P-256)",
        openssl_name: "P-256",
        iana_value: 23,
        group_type: GroupType::EllipticCurve,
        bits: 256,
        quantum_vulnerable: true,
    },
    GroupSpec {
        name: "secp384r1 (P-384)",
        openssl_name: "P-384",
        iana_value: 24,
        group_type: GroupType::EllipticCurve,
        bits: 384,
        quantum_vulnerable: true,
    },
    GroupSpec {
        name: "secp521r1 (P-521)",
        openssl_name: "P-521",
        iana_value: 25,
        group_type: GroupType::EllipticCurve,
        bits: 521,
        quantum_vulnerable: true,
    },
    GroupSpec {
        name: "x25519",
        openssl_name: "X25519",
        iana_value: 29,
        group_type: GroupType::EllipticCurve,
        bits: 253,
        quantum_vulnerable: true,
    },
    GroupSpec {
        name: "x448",
        openssl_name: "X448",
        iana_value: 30,
        group_type: GroupType::EllipticCurve,
        bits: 448,
        quantum_vulnerable: true,
    },
    // Finite field (DHE, RFC 7919) — quantum-vulnerable (Shor's algorithm).
    GroupSpec {
        name: "ffdhe2048",
        openssl_name: "ffdhe2048",
        iana_value: 256,
        group_type: GroupType::FiniteField,
        bits: 2048,
        quantum_vulnerable: true,
    },
    GroupSpec {
        name: "ffdhe3072",
        openssl_name: "ffdhe3072",
        iana_value: 257,
        group_type: GroupType::FiniteField,
        bits: 3072,
        quantum_vulnerable: true,
    },
    GroupSpec {
        name: "ffdhe4096",
        openssl_name: "ffdhe4096",
        iana_value: 258,
        group_type: GroupType::FiniteField,
        bits: 4096,
        quantum_vulnerable: true,
    },
    GroupSpec {
        name: "ffdhe6144",
        openssl_name: "ffdhe6144",
        iana_value: 259,
        group_type: GroupType::FiniteField,
        bits: 6144,
        quantum_vulnerable: true,
    },
    GroupSpec {
        name: "ffdhe8192",
        openssl_name: "ffdhe8192",
        iana_value: 260,
        group_type: GroupType::FiniteField,
        bits: 8192,
        quantum_vulnerable: true,
    },
    // Post-quantum hybrid groups — quantum-safe.
    GroupSpec {
        name: "X25519Kyber768Draft00",
        openssl_name: "X25519Kyber768Draft00",
        iana_value: 0x6399,
        group_type: GroupType::PostQuantum,
        bits: 768,
        quantum_vulnerable: false,
    },
    GroupSpec {
        name: "X25519MLKEM768",
        openssl_name: "X25519MLKEM768",
        iana_value: 0x11EC,
        group_type: GroupType::PostQuantum,
        bits: 768,
        quantum_vulnerable: false,
    },
];

const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Cipher list that forces a (EC)DHE key exchange for TLS 1.2 and below, so a
/// successful handshake can only have used the single offered group rather than
/// a static-RSA key exchange that ignores groups. TLS 1.3 ciphersuites are not
/// governed by this list and always use a named group.
const GROUP_KX_CIPHER_LIST: &str = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-CHACHA20-POLY1305";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupProbeOutcome {
    /// Server completed a handshake using only this group.
    Supported,
    /// Server rejected a handshake offering only this group.
    NotSupported,
    /// Network/transport error — support could not be determined.
    Inconclusive,
    /// The local OpenSSL build cannot offer this group, so the server's support
    /// cannot be tested (treated as not-supported but excluded from "measured").
    Unprobeable,
}

/// Classify an OpenSSL handshake error string as a transient transport problem
/// (inconclusive) versus a genuine protocol-level rejection (not supported).
fn is_operational_tls_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("unexpected eof")
        || error.contains("connection reset")
        || error.contains("reset by peer")
        || error.contains("connection refused")
        || error.contains("timed out")
        || error.contains("timeout")
        || error.contains("closed")
        || error.contains("shutdown while in init")
        || error.contains("errno=54")
}

pub struct GroupTester {
    target: Target,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    starttls_hostname: Option<String>,
    starttls_server_mode: bool,
    test_all_ips: bool,
}

impl GroupTester {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            starttls: None,
            starttls_hostname: None,
            starttls_server_mode: false,
            test_all_ips: false,
        }
    }

    pub fn with_starttls(
        mut self,
        starttls: Option<crate::starttls::StarttlsProtocol>,
        hostname: Option<String>,
    ) -> Self {
        self.starttls = starttls;
        self.starttls_hostname = hostname;
        self
    }

    pub fn with_starttls_server_mode(mut self, server_mode: bool) -> Self {
        self.starttls_server_mode = server_mode;
        self
    }

    pub fn with_test_all_ips(mut self, enable: bool) -> Self {
        self.test_all_ips = enable;
        self
    }

    pub async fn enumerate_groups(&self) -> Result<GroupEnumerationResult> {
        let mut groups = Vec::with_capacity(GROUP_SPECS.len());
        let mut saw_supported = false;
        let mut saw_not_supported = false;
        let mut saw_inconclusive = false;
        let mut unprobeable = Vec::new();

        for spec in GROUP_SPECS {
            let outcome = self.probe_group(spec.openssl_name).await;
            match outcome {
                GroupProbeOutcome::Supported => saw_supported = true,
                GroupProbeOutcome::NotSupported => saw_not_supported = true,
                GroupProbeOutcome::Inconclusive => saw_inconclusive = true,
                GroupProbeOutcome::Unprobeable => unprobeable.push(spec.name),
            }
            groups.push(KeyExchangeGroup {
                name: spec.name.to_string(),
                iana_value: spec.iana_value,
                group_type: spec.group_type,
                bits: spec.bits,
                supported: outcome == GroupProbeOutcome::Supported,
                quantum_vulnerable: spec.quantum_vulnerable,
            });
        }

        let measured = saw_supported || saw_not_supported;
        let supported: Vec<&str> = groups
            .iter()
            .filter(|g| g.supported)
            .map(|g| g.name.as_str())
            .collect();
        let details = build_details(measured, &supported, &unprobeable, saw_inconclusive);

        Ok(GroupEnumerationResult {
            groups,
            measured,
            details,
        })
    }

    /// Probe whether the server supports a single key exchange group by offering
    /// only that group (and group-using ciphers) in a handshake.
    async fn probe_group(&self, openssl_name: &str) -> GroupProbeOutcome {
        let addrs = self.target.socket_addrs();
        if addrs.is_empty() {
            return GroupProbeOutcome::Inconclusive;
        }

        let hostname = self
            .starttls_hostname
            .clone()
            .unwrap_or_else(|| self.target.hostname.clone());
        let probe_addrs: Vec<_> = if self.test_all_ips {
            addrs
        } else {
            addrs.first().copied().into_iter().collect()
        };

        let openssl_name = openssl_name.to_string();
        let mut saw_supported = false;
        let mut saw_not_supported = false;
        let mut saw_unprobeable = false;
        let mut saw_inconclusive = false;

        for addr in probe_addrs {
            let stream = if let Some(starttls) = self.starttls {
                match crate::utils::network::connect_with_starttls(
                    addr,
                    PROBE_CONNECT_TIMEOUT,
                    Some(starttls),
                    &hostname,
                    self.starttls_server_mode,
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(_) => {
                        saw_inconclusive = true;
                        continue;
                    }
                }
            } else {
                match crate::utils::network::connect_with_timeout(addr, PROBE_CONNECT_TIMEOUT, None)
                    .await
                {
                    Ok(stream) => stream,
                    Err(_) => {
                        saw_inconclusive = true;
                        continue;
                    }
                }
            };

            let std_stream = match crate::utils::network::into_blocking_std_stream(
                stream,
                PROBE_HANDSHAKE_TIMEOUT,
            ) {
                Ok(stream) => stream,
                Err(_) => {
                    saw_inconclusive = true;
                    continue;
                }
            };

            let hostname = self.target.hostname.clone();
            let openssl_name = openssl_name.clone();
            let outcome = match tokio::task::spawn_blocking(move || {
                let mut builder = match SslConnector::builder(SslMethod::tls()) {
                    Ok(builder) => builder,
                    Err(_) => return GroupProbeOutcome::Inconclusive,
                };
                builder.set_verify(SslVerifyMode::NONE);

                // If the local OpenSSL cannot offer this group (e.g. a post-quantum group
                // on an older build), the server's support cannot be determined — report
                // it as unprobeable rather than falsely claiming it is unsupported.
                if builder.set_groups_list(&openssl_name).is_err() {
                    return GroupProbeOutcome::Unprobeable;
                }
                if builder.set_cipher_list(GROUP_KX_CIPHER_LIST).is_err() {
                    return GroupProbeOutcome::Inconclusive;
                }

                let connector = builder.build();
                match connector.connect(&hostname, std_stream) {
                    Ok(_) => GroupProbeOutcome::Supported,
                    Err(error) => {
                        if is_operational_tls_error(&error.to_string()) {
                            GroupProbeOutcome::Inconclusive
                        } else {
                            GroupProbeOutcome::NotSupported
                        }
                    }
                }
            })
            .await
            {
                Ok(outcome) => outcome,
                Err(_) => GroupProbeOutcome::Inconclusive,
            };

            match outcome {
                GroupProbeOutcome::Supported => saw_supported = true,
                GroupProbeOutcome::NotSupported => saw_not_supported = true,
                GroupProbeOutcome::Unprobeable => saw_unprobeable = true,
                GroupProbeOutcome::Inconclusive => saw_inconclusive = true,
            }
        }

        if saw_supported {
            GroupProbeOutcome::Supported
        } else if saw_not_supported {
            GroupProbeOutcome::NotSupported
        } else if saw_unprobeable {
            GroupProbeOutcome::Unprobeable
        } else if saw_inconclusive {
            GroupProbeOutcome::Inconclusive
        } else {
            GroupProbeOutcome::Inconclusive
        }
    }
}

/// Build the human-readable summary for a group enumeration result.
fn build_details(
    measured: bool,
    supported: &[&str],
    unprobeable: &[&str],
    saw_inconclusive: bool,
) -> String {
    if !measured {
        return "Key exchange group support could not be measured — no group probe \
                completed a conclusive handshake (target unreachable or every probe errored)."
            .to_string();
    }

    let mut details = if supported.is_empty() {
        "No configured key exchange group was negotiated.".to_string()
    } else {
        format!("Supported key exchange groups: {}.", supported.join(", "))
    };

    if !unprobeable.is_empty() {
        details.push_str(&format!(
            " Not testable with the local TLS library: {}.",
            unprobeable.join(", ")
        ));
    }
    if saw_inconclusive {
        details.push_str(" Some group probes were inconclusive due to transport errors.");
    }

    details
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_group_enumeration_unreachable_target_is_not_measured() {
        let target = Target::with_ips(
            "localhost".to_string(),
            9, // discard port, likely closed
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = GroupTester::new(target);

        let result = tester
            .enumerate_groups()
            .await
            .expect("test assertion should succeed");

        // Every probe fails to connect, so support is inconclusive: nothing is
        // reported supported and the result is honestly marked unmeasured.
        assert!(!result.measured);
        assert!(result.groups.iter().all(|g| !g.supported));
        assert!(result.details.contains("could not be measured"));
    }

    #[tokio::test]
    async fn test_group_enumeration_catalog_is_complete_and_classified() {
        let target = Target::with_ips(
            "localhost".to_string(),
            9,
            vec!["127.0.0.1".parse().expect("valid IP")],
        )
        .expect("test assertion should succeed");
        let tester = GroupTester::new(target);

        let result = tester
            .enumerate_groups()
            .await
            .expect("test assertion should succeed");

        // All classical EC/FFDHE groups are quantum-vulnerable; the two hybrid
        // groups are quantum-safe. This classification feeds PQC readiness.
        assert_eq!(result.groups.len(), 12);
        let pq_safe: Vec<_> = result
            .groups
            .iter()
            .filter(|g| !g.quantum_vulnerable)
            .map(|g| g.name.as_str())
            .collect();
        assert_eq!(pq_safe, vec!["X25519Kyber768Draft00", "X25519MLKEM768"]);
        assert!(
            result
                .groups
                .iter()
                .filter(|g| matches!(g.group_type, GroupType::PostQuantum))
                .all(|g| !g.quantum_vulnerable)
        );
    }

    #[test]
    fn test_group_type_serde_roundtrip() {
        let group = GroupType::PostQuantum;
        let json = serde_json::to_string(&group).expect("serialize");
        let decoded: GroupType = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, GroupType::PostQuantum));
    }

    #[test]
    fn test_group_enumeration_result_empty() {
        let result = GroupEnumerationResult {
            groups: Vec::new(),
            measured: false,
            details: String::new(),
        };
        assert!(result.groups.is_empty());
    }

    #[test]
    fn test_starttls_configuration_is_stored() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![std::net::IpAddr::from([127, 0, 0, 1])],
        )
        .unwrap();

        let tester = GroupTester::new(target)
            .with_starttls(Some(crate::starttls::StarttlsProtocol::XMPP), Some("xmpp.example.com".to_string()))
            .with_starttls_server_mode(true);

        assert_eq!(tester.starttls, Some(crate::starttls::StarttlsProtocol::XMPP));
        assert_eq!(tester.starttls_hostname.as_deref(), Some("xmpp.example.com"));
        assert!(tester.starttls_server_mode);
    }

    #[test]
    fn test_test_all_ips_flag_is_stored() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec![
                std::net::IpAddr::from([127, 0, 0, 1]),
                std::net::IpAddr::from([127, 0, 0, 2]),
            ],
        )
        .unwrap();

        let tester = GroupTester::new(target).with_test_all_ips(true);
        assert!(tester.test_all_ips);
    }
}
