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

        if self.starttls.rdp && self.has_starttls_negotiation_request() {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine --rdp with STARTTLS negotiation options.".to_string(),
            });
        }

        if self.scan.heartbleed && self.scan.no_heartbleed {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine Heartbleed testing with --no-heartbleed.".to_string(),
            });
        }

        if self.scan.fallback && self.scan.no_fallback {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine TLS fallback testing with --no-fallback.".to_string(),
            });
        }

        if self.scan.renegotiation && self.scan.no_renegotiation {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine renegotiation testing with --no-renegotiation."
                    .to_string(),
            });
        }

        if self.scan.crime && self.scan.no_compression {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine CRIME testing with --no-compression.".to_string(),
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
}
