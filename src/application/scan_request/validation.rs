use super::ScanRequest;
use crate::{Result, TlsError};

fn invalid_input(message: impl Into<String>) -> TlsError {
    TlsError::InvalidInput {
        message: message.into(),
    }
}

impl ScanRequest {
    pub fn validate_common(&self) -> Result<()> {
        if self.network.test_all_ips && self.network.first_ip_only {
            return Err(invalid_input(
                "Cannot use --test-all-ips and --first-ip-only together. Choose one scanning mode.",
            ));
        }

        if self.ip.is_some() && self.network.test_all_ips {
            return Err(invalid_input(
                "Cannot use --ip with --test-all-ips. The --ip flag specifies a single IP to scan.",
            ));
        }

        if self.ip.is_some() && self.network.first_ip_only {
            return Err(invalid_input(
                "Cannot use --ip with --first-ip-only. The --ip flag already specifies a single IP to scan.",
            ));
        }

        if self.network.ipv4_only && self.network.ipv6_only {
            return Err(invalid_input(
                "Cannot enable both IPv4-only and IPv6-only scanning.",
            ));
        }

        if self.network.max_concurrent_ciphers == 0 {
            return Err(invalid_input(
                "Max concurrent cipher tests must be greater than 0.",
            ));
        }

        if let Some(ip_override) = self.ip.as_deref() {
            let ip = ip_override
                .parse::<std::net::IpAddr>()
                .map_err(|_| invalid_input(format!("Invalid IP override: {}", ip_override)))?;

            self.network
                .validate_resolved_ips(&[ip])
                .map_err(|error| invalid_input(format!("Invalid IP override: {}", error)))?;

            if self.network.ipv4_only && ip.is_ipv6() {
                return Err(invalid_input(
                    "Cannot use an IPv6 --ip override with IPv4-only scanning.",
                ));
            }
            if self.network.ipv6_only && ip.is_ipv4() {
                return Err(invalid_input(
                    "Cannot use an IPv4 --ip override with IPv6-only scanning.",
                ));
            }
        }

        if let Some(proxy) = &self.network.proxy {
            crate::utils::proxy::ProxyConfig::parse(proxy).map_err(|error| {
                invalid_input(format!("Invalid proxy configuration: {}", error))
            })?;
        }

        if !self.network.resolvers.is_empty() {
            crate::utils::custom_resolvers::CustomResolver::new(self.network.resolvers.clone())
                .map_err(|error| {
                    invalid_input(format!("Invalid custom resolver list: {}", error))
                })?;
        }

        if matches!(self.connection.socket_timeout, Some(0)) {
            return Err(invalid_input(
                "Socket timeout must be greater than 0 seconds.",
            ));
        }

        if matches!(self.connection.connect_timeout, Some(0)) {
            return Err(invalid_input(
                "Connect timeout must be greater than 0 seconds.",
            ));
        }

        if matches!(self.tls.openssl_timeout, Some(0)) {
            return Err(invalid_input(
                "OpenSSL timeout must be greater than 0 seconds.",
            ));
        }

        if let Some(sni_name) = self.tls.sni_name.as_deref() {
            crate::security::validate_hostname(sni_name)
                .map_err(|error| invalid_input(format!("Invalid SNI hostname: {}", error)))?;
            let normalized_sni_name = sni_name.trim_end_matches('.').to_ascii_lowercase();
            if !self.network.permits_private_resolution()
                && (normalized_sni_name == "localhost"
                    || normalized_sni_name.ends_with(".local")
                    || normalized_sni_name.ends_with(".internal"))
            {
                return Err(invalid_input(
                    "Invalid SNI hostname: private/local hostnames are not allowed",
                ));
            }
            if sni_name.ends_with('.') {
                return Err(invalid_input(
                    "Invalid SNI hostname: SNI must not include a trailing dot.",
                ));
            }
            if sni_name.parse::<std::net::IpAddr>().is_ok() {
                return Err(invalid_input(
                    "Invalid SNI hostname: SNI must be a DNS name, not an IP address.",
                ));
            }
        }

        if self.tls.client_key.is_some() ^ self.tls.client_certs.is_some() {
            return Err(invalid_input(
                "mTLS separate key mode requires both --pk and --certs.",
            ));
        }

        if self.tls.mtls_cert.is_some()
            && (self.tls.client_key.is_some() || self.tls.client_certs.is_some())
        {
            return Err(invalid_input("Cannot combine --mtls with --pk/--certs."));
        }

        if self.tls.client_key_password.is_some()
            && self.tls.client_key.is_none()
            && self.tls.mtls_cert.is_none()
        {
            return Err(invalid_input("--pkpass requires --pk or --mtls."));
        }

        if self.tls.ech
            && (self.tls.mtls_cert.is_some()
                || self.tls.client_key.is_some()
                || self.tls.client_certs.is_some())
        {
            return Err(invalid_input(
                "Cannot combine --ech with client certificate authentication.",
            ));
        }

        if let Some(format) = &self.fingerprint.export_hello {
            crate::output::hello_export::HelloExportFormat::parse(format)?;
        }

        if let Some(path) = &self.fingerprint.ja3_database {
            crate::fingerprint::Ja3Database::from_file(path)
                .map_err(|error| invalid_input(format!("Invalid JA3 database: {}", error)))?;
        }

        if let Some(path) = &self.fingerprint.ja3s_database {
            crate::fingerprint::Ja3sDatabase::from_file(path)
                .map_err(|error| invalid_input(format!("Invalid JA3S database: {}", error)))?;
        }

        if let Some(path) = &self.fingerprint.jarm_database {
            crate::fingerprint::JarmDatabase::from_file(path)
                .map_err(|error| invalid_input(format!("Invalid JARM database: {}", error)))?;
        }

        if self.connection.retry_backoff_ms > self.connection.max_backoff_ms {
            return Err(invalid_input(
                "Retry backoff cannot be greater than max backoff.",
            ));
        }

        if self.starttls.protocol.is_some() && self.starttls_protocol().is_none() {
            return Err(invalid_input("Unsupported STARTTLS protocol specified."));
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
            return Err(invalid_input(
                "Cannot combine multiple STARTTLS protocol options.",
            ));
        }

        if let Some(xmpphost) = self.starttls.xmpphost.as_deref() {
            crate::security::validate_hostname(xmpphost)
                .map_err(|error| invalid_input(format!("Invalid XMPP hostname: {}", error)))?;
            if xmpphost.ends_with('.') {
                return Err(invalid_input(
                    "Invalid XMPP hostname: --xmpphost must not include a trailing dot.",
                ));
            }

            if !matches!(
                self.starttls_protocol(),
                Some(crate::starttls::StarttlsProtocol::XMPP)
            ) {
                return Err(invalid_input("--xmpphost requires an XMPP STARTTLS mode."));
            }
        }

        if self.starttls.rdp && self.has_starttls_negotiation_request() {
            return Err(invalid_input(
                "Cannot combine --rdp with STARTTLS negotiation options.",
            ));
        }

        if self.scan.vulns.heartbleed && self.scan.vulns.no_heartbleed {
            return Err(invalid_input(
                "Cannot combine Heartbleed testing with --no-heartbleed.",
            ));
        }

        if self.scan.vulns.fallback && self.scan.vulns.no_fallback {
            return Err(invalid_input(
                "Cannot combine TLS fallback testing with --no-fallback.",
            ));
        }

        if self.scan.vulns.renegotiation && self.scan.vulns.no_renegotiation {
            return Err(invalid_input(
                "Cannot combine renegotiation testing with --no-renegotiation.",
            ));
        }

        if self.scan.vulns.crime && self.scan.vulns.no_compression {
            return Err(invalid_input(
                "Cannot combine CRIME testing with --no-compression.",
            ));
        }

        if self.tls.hardfail && !self.tls.phone_out {
            return Err(invalid_input("Cannot use --hardfail without --phone-out."));
        }

        if self.tls.ssl_native && !self.tls.local && !self.should_run_certificate_phase() {
            return Err(invalid_input(
                "--ssl-native requires a scan that runs certificate analysis or --local.",
            ));
        }

        if (self.tls.openssl_path.is_some() || self.tls.openssl_timeout.is_some())
            && !self.tls.local
            && !self.tls.ssl_native
        {
            return Err(invalid_input(
                "--openssl and --openssl-timeout are only used with --ssl-native or --local.",
            ));
        }

        if self.tls.add_ca.is_some() && !self.should_run_certificate_phase() {
            return Err(invalid_input(
                "--add-ca requires a scan that runs certificate analysis.",
            ));
        }

        Ok(())
    }

    pub fn validate_for_scan(&self) -> Result<()> {
        self.validate_common()?;

        match self.target.as_deref().map(str::trim) {
            Some("") | None => Err(invalid_input("A target is required for scan execution.")),
            Some(_) if !self.has_effective_scan_workload() => Err(invalid_input(
                "Scan request must enable at least one effective scan phase.",
            )),
            Some(_) => Ok(()),
        }
    }
}
