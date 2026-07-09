use super::ScanRequest;
use crate::protocols::Protocol;
use crate::starttls::StarttlsProtocol;
use crate::utils::retry::RetryConfig;
use std::time::Duration;

impl ScanRequest {
    pub fn protocols_to_test(&self) -> Option<Vec<Protocol>> {
        let flags = [
            (self.scan.proto.ssl2, Protocol::SSLv2),
            (self.scan.proto.ssl3, Protocol::SSLv3),
            (self.scan.proto.tls10, Protocol::TLS10),
            (self.scan.proto.tls11, Protocol::TLS11),
            (self.scan.proto.tls12, Protocol::TLS12),
            (self.scan.proto.tls13, Protocol::TLS13),
        ];

        let selected: Vec<Protocol> = flags
            .iter()
            .filter(|(enabled, _)| *enabled)
            .map(|(_, proto)| *proto)
            .collect();

        if !selected.is_empty() {
            return Some(selected);
        }

        if self.scan.proto.tlsall {
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
        } else if self.starttls.nntp {
            Some(NNTP)
        } else if self.starttls.sieve {
            Some(SIEVE)
        } else if self.starttls.lmtp {
            Some(LMTP)
        } else {
            let protocol = self
                .starttls
                .protocol
                .as_deref()?
                .trim()
                .to_ascii_lowercase();
            match protocol.as_str() {
                "smtp" => Some(SMTP),
                "imap" => Some(IMAP),
                "pop3" => Some(POP3),
                "ftp" => Some(FTP),
                "ldap" => Some(LDAP),
                "xmpp" | "xmpp-server" => Some(XMPP),
                "postgres" | "postgresql" | "psql" => Some(POSTGRES),
                "mysql" => Some(MYSQL),
                "irc" => Some(IRC),
                "nntp" => Some(NNTP),
                "sieve" => Some(SIEVE),
                "lmtp" => Some(LMTP),
                "telnet" => Some(Telnet),
                _ => None,
            }
        }
    }

    pub fn starttls_port(&self) -> Option<u16> {
        if self.starttls.smtp {
            Some(25)
        } else if self.starttls.imap {
            Some(143)
        } else if self.starttls.pop3 {
            Some(110)
        } else if self.starttls.ftp {
            Some(21)
        } else if self.starttls.ldap {
            Some(389)
        } else if self.starttls.xmpp {
            Some(5222)
        } else if self.starttls.xmpp_server {
            Some(5269)
        } else if self.starttls.psql {
            Some(5432)
        } else if self.starttls.mysql {
            Some(3306)
        } else if self.starttls.irc {
            Some(6667)
        } else if self.starttls.nntp {
            Some(119)
        } else if self.starttls.sieve {
            Some(4190)
        } else if self.starttls.lmtp {
            Some(24)
        } else {
            let protocol = self
                .starttls
                .protocol
                .as_deref()?
                .trim()
                .to_ascii_lowercase();
            match protocol.as_str() {
                "smtp" => Some(25),
                "imap" => Some(143),
                "pop3" => Some(110),
                "ftp" => Some(21),
                "ldap" => Some(389),
                "xmpp" => Some(5222),
                "xmpp-server" => Some(5269),
                "postgres" | "postgresql" | "psql" => Some(5432),
                "mysql" => Some(3306),
                "irc" => Some(6667),
                "nntp" => Some(119),
                "sieve" => Some(4190),
                "lmtp" => Some(24),
                _ => None,
            }
        }
    }

    pub fn starttls_server_mode(&self) -> bool {
        self.starttls.xmpp_server
            || self
                .starttls
                .protocol
                .as_deref()
                .map(str::trim)
                .is_some_and(|protocol| protocol.eq_ignore_ascii_case("xmpp-server"))
    }

    pub fn has_specific_scan_focus(&self) -> bool {
        self.scan.proto.enabled
            || self.protocols_to_test().is_some()
            || self.scan.ciphers.each_cipher
            || self.scan.ciphers.cipher_per_proto
            || self.scan.ciphers.categories
            || self.scan.ciphers.forward_secrecy
            || self.scan.ciphers.server_defaults
            || self.scan.ciphers.server_preference
            || self.scan.prefs.headers
            || self.scan.vulns.vulnerabilities
            || self.scan.certs.analyze_certificates
            || self.has_specific_vulnerability_focus()
            || self.has_explicit_fingerprint_focus()
            || self.fingerprint.client_simulation
            || self.scan.certs.ocsp
            || self.scan.prefs.pre_handshake
            || self.scan.prefs.probe_status
            || self.scan.ciphers.show_sigs
            || self.scan.ciphers.show_groups
            || self.scan.ciphers.show_client_cas
    }

    pub fn has_specific_vulnerability_focus(&self) -> bool {
        self.scan.vulns.heartbleed
            || self.scan.vulns.ccs
            || self.scan.vulns.ticketbleed
            || self.scan.vulns.robot
            || self.scan.vulns.renegotiation
            || self.scan.vulns.crime
            || self.scan.vulns.breach
            || self.scan.vulns.poodle
            || self.scan.vulns.fallback
            || self.scan.vulns.sweet32
            || self.scan.vulns.beast
            || self.scan.vulns.lucky13
            || self.scan.vulns.freak
            || self.scan.vulns.logjam
            || self.scan.vulns.drown
            || self.scan.vulns.early_data
    }

    pub(crate) fn has_starttls_negotiation_request(&self) -> bool {
        self.starttls.protocol.is_some()
            || self.starttls.smtp
            || self.starttls.imap
            || self.starttls.pop3
            || self.starttls.ftp
            || self.starttls.ldap
            || self.starttls.xmpp
            || self.starttls.psql
            || self.starttls.mysql
            || self.starttls.irc
            || self.starttls.xmpp_server
            || self.starttls.nntp
            || self.starttls.sieve
            || self.starttls.lmtp
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
mod extra_tests {
    use super::*;

    #[test]
    fn starttls_server_mode_detects_xmpp_server_alias() {
        let request = ScanRequest {
            starttls: crate::application::scan_request::ScanRequestStarttls {
                protocol: Some(" xmpp-server ".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(request.starttls_server_mode());
    }
}
