use crate::protocols::Protocol;
use crate::starttls::StarttlsProtocol;
use crate::utils::retry::RetryConfig;
use crate::{Result, TlsError};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct ScanRequest {
    pub target: Option<String>,
    pub port: Option<u16>,
    pub ip: Option<String>,
    pub scan: ScanRequestScan,
    pub network: ScanRequestNetwork,
    pub connection: ScanRequestConnection,
    pub tls: ScanRequestTls,
    pub fingerprint: ScanRequestFingerprint,
    pub http: ScanRequestHttp,
    pub starttls: ScanRequestStarttls,
    pub ct_logs: ScanRequestCtLogs,
}

#[derive(Debug, Clone, Default)]
pub struct ScanRequestScan {
    pub protocols: bool,
    pub each_cipher: bool,
    pub vulnerabilities: bool,
    pub headers: bool,
    pub all: bool,
    pub full: bool,
    pub no_ciphersuites: bool,
    pub no_fallback: bool,
    pub no_compression: bool,
    pub no_heartbleed: bool,
    pub no_renegotiation: bool,
    pub no_check_certificate: bool,
    pub show_sigs: bool,
    pub show_groups: bool,
    pub no_groups: bool,
    pub show_client_cas: bool,
    pub ssl2: bool,
    pub ssl3: bool,
    pub tls10: bool,
    pub tls11: bool,
    pub tls12: bool,
    pub tls13: bool,
    pub tlsall: bool,
}

#[derive(Debug, Clone)]
pub struct ScanRequestNetwork {
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub test_all_ips: bool,
    pub first_ip_only: bool,
    pub max_concurrent_ciphers: usize,
}

impl Default for ScanRequestNetwork {
    fn default() -> Self {
        Self {
            ipv4_only: false,
            ipv6_only: false,
            test_all_ips: false,
            first_ip_only: false,
            max_concurrent_ciphers: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanRequestConnection {
    pub socket_timeout: Option<u64>,
    pub connect_timeout: Option<u64>,
    pub sleep: Option<u64>,
    pub max_retries: usize,
    pub retry_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub no_retry: bool,
}

impl Default for ScanRequestConnection {
    fn default() -> Self {
        Self {
            socket_timeout: None,
            connect_timeout: None,
            sleep: None,
            max_retries: 3,
            retry_backoff_ms: 100,
            max_backoff_ms: 5000,
            no_retry: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanRequestTls {
    pub bugs: bool,
    pub phone_out: bool,
    pub hardfail: bool,
    pub sni_name: Option<String>,
    pub mtls_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub client_key_password: Option<String>,
    pub client_certs: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ScanRequestFingerprint {
    pub ja3: bool,
    pub client_hello: bool,
    pub ja3_database: Option<PathBuf>,
    pub ja3s: bool,
    pub server_hello: bool,
    pub ja3s_database: Option<PathBuf>,
    pub jarm: bool,
    pub jarm_database: Option<PathBuf>,
    pub client_simulation: bool,
}

impl Default for ScanRequestFingerprint {
    fn default() -> Self {
        Self {
            ja3: true,
            client_hello: false,
            ja3_database: None,
            ja3s: true,
            server_hello: false,
            ja3s_database: None,
            jarm: true,
            jarm_database: None,
            client_simulation: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanRequestHttp {
    pub custom_headers: Vec<String>,
    pub sneaky: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ScanRequestStarttls {
    pub protocol: Option<String>,
    pub smtp: bool,
    pub imap: bool,
    pub pop3: bool,
    pub ftp: bool,
    pub ldap: bool,
    pub xmpp: bool,
    pub psql: bool,
    pub mysql: bool,
    pub irc: bool,
    pub xmpp_server: bool,
    pub rdp: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ScanRequestCtLogs {
    pub enable: bool,
}

impl ScanRequest {
    pub fn has_target(&self) -> bool {
        self.target.is_some()
    }

    pub fn validate_common(&self) -> Result<()> {
        if self.network.test_all_ips && self.network.first_ip_only {
            return Err(TlsError::InvalidInput {
                message: "Cannot use --test-all-ips and --first-ip-only together. Choose one scanning mode.".to_string(),
            });
        }

        if self.ip.is_some() && self.network.test_all_ips {
            return Err(TlsError::InvalidInput {
                message: "Cannot use --ip with --test-all-ips. The --ip flag specifies a single IP to scan.".to_string(),
            });
        }

        if self.ip.is_some() && self.network.first_ip_only {
            return Err(TlsError::InvalidInput {
                message: "Cannot use --ip with --first-ip-only. The --ip flag already specifies a single IP to scan.".to_string(),
            });
        }

        if self.network.ipv4_only && self.network.ipv6_only {
            return Err(TlsError::InvalidInput {
                message: "Cannot enable both IPv4-only and IPv6-only scanning.".to_string(),
            });
        }

        if matches!(self.connection.socket_timeout, Some(0)) {
            return Err(TlsError::InvalidInput {
                message: "Socket timeout must be greater than 0 seconds.".to_string(),
            });
        }

        if matches!(self.connection.connect_timeout, Some(0)) {
            return Err(TlsError::InvalidInput {
                message: "Connect timeout must be greater than 0 seconds.".to_string(),
            });
        }

        if self.connection.retry_backoff_ms > self.connection.max_backoff_ms {
            return Err(TlsError::InvalidInput {
                message: "Retry backoff cannot be greater than max backoff.".to_string(),
            });
        }

        if self.starttls.protocol.is_some() && self.starttls_protocol().is_none() {
            return Err(TlsError::InvalidInput {
                message: "Unsupported STARTTLS protocol specified.".to_string(),
            });
        }

        Ok(())
    }

    pub fn validate_for_scan(&self) -> Result<()> {
        self.validate_common()?;

        match self.target.as_deref().map(str::trim) {
            Some("") | None => Err(TlsError::InvalidInput {
                message: "A target is required for scan execution.".to_string(),
            }),
            Some(_) => Ok(()),
        }
    }

    pub fn protocols_to_test(&self) -> Option<Vec<Protocol>> {
        if self.scan.ssl2
            || self.scan.ssl3
            || self.scan.tls10
            || self.scan.tls11
            || self.scan.tls12
            || self.scan.tls13
        {
            let mut protocols = Vec::new();
            if self.scan.ssl2 {
                protocols.push(Protocol::SSLv2);
            }
            if self.scan.ssl3 {
                protocols.push(Protocol::SSLv3);
            }
            if self.scan.tls10 {
                protocols.push(Protocol::TLS10);
            }
            if self.scan.tls11 {
                protocols.push(Protocol::TLS11);
            }
            if self.scan.tls12 {
                protocols.push(Protocol::TLS12);
            }
            if self.scan.tls13 {
                protocols.push(Protocol::TLS13);
            }
            return Some(protocols);
        }

        if self.scan.tlsall {
            return Some(vec![
                Protocol::TLS10,
                Protocol::TLS11,
                Protocol::TLS12,
                Protocol::TLS13,
            ]);
        }

        None
    }

    pub fn starttls_protocol(&self) -> Option<StarttlsProtocol> {
        use StarttlsProtocol::*;

        if self.starttls.smtp {
            Some(SMTP)
        } else if self.starttls.imap {
            Some(IMAP)
        } else if self.starttls.pop3 {
            Some(POP3)
        } else if self.starttls.ftp {
            Some(FTP)
        } else if self.starttls.ldap {
            Some(LDAP)
        } else if self.starttls.xmpp || self.starttls.xmpp_server {
            Some(XMPP)
        } else if self.starttls.psql {
            Some(POSTGRES)
        } else if self.starttls.mysql {
            Some(MYSQL)
        } else if self.starttls.irc {
            Some(IRC)
        } else {
            match self.starttls.protocol.as_deref() {
                Some("smtp") => Some(SMTP),
                Some("imap") => Some(IMAP),
                Some("pop3") => Some(POP3),
                Some("ftp") => Some(FTP),
                Some("ldap") => Some(LDAP),
                Some("xmpp") => Some(XMPP),
                Some("postgres") | Some("postgresql") | Some("psql") => Some(POSTGRES),
                Some("mysql") => Some(MYSQL),
                Some("irc") => Some(IRC),
                _ => None,
            }
        }
    }

    pub fn retry_config(&self) -> Option<RetryConfig> {
        if self.connection.no_retry || self.connection.max_retries == 0 {
            return None;
        }

        Some(RetryConfig::new(
            self.connection.max_retries,
            Duration::from_millis(self.connection.retry_backoff_ms),
            Duration::from_millis(self.connection.max_backoff_ms),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::request::ScanOptions;

    #[test]
    fn maps_scan_options_into_internal_request() {
        let options = ScanOptions::full();
        let request = ScanRequest {
            target: Some("example.com:443".to_string()),
            scan: ScanRequestScan {
                protocols: options.test_protocols || options.full_scan,
                each_cipher: options.test_ciphers || options.full_scan,
                vulnerabilities: options.test_vulnerabilities || options.full_scan,
                headers: options.test_http_headers || options.full_scan,
                all: options.full_scan,
                full: options.full_scan,
                ..Default::default()
            },
            fingerprint: ScanRequestFingerprint {
                client_simulation: options.client_simulation || options.full_scan,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(request.target.as_deref(), Some("example.com:443"));
        assert!(request.scan.protocols);
        assert!(request.scan.each_cipher);
        assert!(request.scan.vulnerabilities);
        assert!(request.scan.headers);
        assert!(request.scan.all);
        assert!(request.fingerprint.client_simulation);
    }

    #[test]
    fn builds_protocol_filter_from_flags() {
        let request = ScanRequest {
            scan: ScanRequestScan {
                ssl2: true,
                tls13: true,
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(
            request.protocols_to_test(),
            Some(vec![Protocol::SSLv2, Protocol::TLS13])
        );
    }

    #[test]
    fn rejects_conflicting_ip_scan_modes() {
        let request = ScanRequest {
            ip: Some("127.0.0.1".to_string()),
            network: ScanRequestNetwork {
                test_all_ips: true,
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(request.validate_common().is_err());
    }

    #[test]
    fn rejects_missing_target_for_scan() {
        let request = ScanRequest::default();
        assert!(request.validate_for_scan().is_err());
    }
}
