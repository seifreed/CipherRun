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
                Some("nntp") => Some(NNTP),
                Some("sieve") => Some(SIEVE),
                Some("lmtp") => Some(LMTP),
                _ => None,
            }
        }
    }

    pub fn has_specific_scan_focus(&self) -> bool {
        self.scan.proto.enabled
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
