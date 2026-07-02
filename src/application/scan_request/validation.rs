use super::ScanRequest;
use crate::{Result, TlsError};

impl ScanRequest {
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

        if self.network.max_concurrent_ciphers == 0 {
            return Err(TlsError::InvalidInput {
                message: "Max concurrent cipher tests must be greater than 0.".to_string(),
            });
        }

        if let Some(ip_override) = self.ip.as_deref() {
            let ip =
                ip_override
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| TlsError::InvalidInput {
                        message: format!("Invalid IP override: {}", ip_override),
                    })?;

            crate::security::input_validation::validate_resolved_ips(&[ip], false).map_err(
                |error| TlsError::InvalidInput {
                    message: format!("Invalid IP override: {}", error),
                },
            )?;

            if self.network.ipv4_only && ip.is_ipv6() {
                return Err(TlsError::InvalidInput {
                    message: "Cannot use an IPv6 --ip override with IPv4-only scanning."
                        .to_string(),
                });
            }
            if self.network.ipv6_only && ip.is_ipv4() {
                return Err(TlsError::InvalidInput {
                    message: "Cannot use an IPv4 --ip override with IPv6-only scanning."
                        .to_string(),
                });
            }
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

        if let Some(sni_name) = self.tls.sni_name.as_deref() {
            crate::security::validate_hostname(sni_name).map_err(|error| {
                TlsError::InvalidInput {
                    message: format!("Invalid SNI hostname: {}", error),
                }
            })?;
            if sni_name.ends_with('.') {
                return Err(TlsError::InvalidInput {
                    message: "Invalid SNI hostname: SNI must not include a trailing dot."
                        .to_string(),
                });
            }
            if sni_name.parse::<std::net::IpAddr>().is_ok() {
                return Err(TlsError::InvalidInput {
                    message: "Invalid SNI hostname: SNI must be a DNS name, not an IP address."
                        .to_string(),
                });
            }
        }

        if self.tls.client_key.is_some() ^ self.tls.client_certs.is_some() {
            return Err(TlsError::InvalidInput {
                message: "mTLS separate key mode requires both --pk and --certs.".to_string(),
            });
        }

        if self.tls.mtls_cert.is_some()
            && (self.tls.client_key.is_some() || self.tls.client_certs.is_some())
        {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine --mtls with --pk/--certs.".to_string(),
            });
        }

        if self.tls.client_key_password.is_some() && self.tls.client_key.is_none() {
            return Err(TlsError::InvalidInput {
                message: "--pkpass requires --pk.".to_string(),
            });
        }

        if let Some(format) = &self.fingerprint.export_hello {
            crate::output::hello_export::HelloExportFormat::parse(format)?;
        }

        if let Some(path) = &self.fingerprint.ja3_database {
            crate::fingerprint::Ja3Database::from_file(path).map_err(|error| {
                TlsError::InvalidInput {
                    message: format!("Invalid JA3 database: {}", error),
                }
            })?;
        }

        if let Some(path) = &self.fingerprint.ja3s_database {
            crate::fingerprint::Ja3sDatabase::from_file(path).map_err(|error| {
                TlsError::InvalidInput {
                    message: format!("Invalid JA3S database: {}", error),
                }
            })?;
        }

        if let Some(path) = &self.fingerprint.jarm_database {
            crate::fingerprint::JarmDatabase::from_file(path).map_err(|error| {
                TlsError::InvalidInput {
                    message: format!("Invalid JARM database: {}", error),
                }
            })?;
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

        let starttls_modes = [
            self.starttls.protocol.is_some(),
            self.starttls.smtp,
            self.starttls.imap,
            self.starttls.pop3,
            self.starttls.ftp,
            self.starttls.ldap,
            self.starttls.xmpp,
            self.starttls.psql,
            self.starttls.mysql,
            self.starttls.irc,
            self.starttls.xmpp_server,
            self.starttls.nntp,
            self.starttls.sieve,
            self.starttls.lmtp,
        ]
        .into_iter()
        .filter(|enabled| *enabled)
        .count();
        if starttls_modes > 1 {
            return Err(TlsError::InvalidInput {
                message: "Cannot combine multiple STARTTLS protocol options.".to_string(),
            });
        }

        if let Some(xmpphost) = self.starttls.xmpphost.as_deref() {
            crate::security::validate_hostname(xmpphost).map_err(|error| {
                TlsError::InvalidInput {
                    message: format!("Invalid XMPP hostname: {}", error),
                }
            })?;
            if xmpphost.ends_with('.') {
                return Err(TlsError::InvalidInput {
                    message: "Invalid XMPP hostname: --xmpphost must not include a trailing dot."
                        .to_string(),
                });
            }

            if !matches!(
                self.starttls_protocol(),
                Some(crate::starttls::StarttlsProtocol::XMPP)
            ) {
                return Err(TlsError::InvalidInput {
                    message: "--xmpphost requires an XMPP STARTTLS mode.".to_string(),
                });
            }
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
