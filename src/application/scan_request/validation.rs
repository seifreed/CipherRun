use super::ScanRequest;
use crate::{Result, TlsError};

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

        if let Some(proxy) = &self.network.proxy {
            crate::utils::proxy::ProxyConfig::parse(proxy).map_err(|error| {
                TlsError::InvalidInput {
                    message: format!("Invalid proxy configuration: {}", error),
                }
            })?;
        }

        if !self.network.resolvers.is_empty() {
            crate::utils::custom_resolvers::CustomResolver::new(self.network.resolvers.clone())
                .map_err(|error| TlsError::InvalidInput {
                    message: format!("Invalid custom resolver list: {}", error),
                })?;
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

        if matches!(self.tls.openssl_timeout, Some(0)) {
            return Err(TlsError::InvalidInput {
                message: "OpenSSL timeout must be greater than 0 seconds.".to_string(),
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

        if self.starttls.rdp && self.has_starttls_negotiation_request() {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine --rdp with STARTTLS negotiation options.".to_string(),
            });
        }

        if self.scan.vulns.heartbleed && self.scan.vulns.no_heartbleed {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine Heartbleed testing with --no-heartbleed.".to_string(),
            });
        }

        if self.scan.vulns.fallback && self.scan.vulns.no_fallback {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine TLS fallback testing with --no-fallback.".to_string(),
            });
        }

        if self.scan.vulns.renegotiation && self.scan.vulns.no_renegotiation {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine renegotiation testing with --no-renegotiation."
                    .to_string(),
            });
        }

        if self.scan.vulns.crime && self.scan.vulns.no_compression {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine CRIME testing with --no-compression.".to_string(),
            });
        }

        if self.tls.hardfail && !self.tls.phone_out {
            return Err(TlsError::InvalidInput {
                message: "Cannot use --hardfail without --phone-out.".to_string(),
            });
        }

        if self.tls.ssl_native && !self.tls.local && !self.should_run_certificate_phase() {
            return Err(TlsError::InvalidInput {
                message: "--ssl-native requires a scan that runs certificate analysis or --local."
                    .to_string(),
            });
        }

        if (self.tls.openssl_path.is_some() || self.tls.openssl_timeout.is_some())
            && !self.tls.local
            && !self.tls.ssl_native
        {
            return Err(TlsError::InvalidInput {
                message:
                    "--openssl and --openssl-timeout are only used with --ssl-native or --local."
                        .to_string(),
            });
        }

        if self.tls.add_ca.is_some() && !self.should_run_certificate_phase() {
            return Err(TlsError::InvalidInput {
                message: "--add-ca requires a scan that runs certificate analysis.".to_string(),
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
            Some(_) if !self.has_effective_scan_workload() => Err(TlsError::InvalidInput {
                message: "Scan request must enable at least one effective scan phase.".to_string(),
            }),
            Some(_) => Ok(()),
        }
    }
}
