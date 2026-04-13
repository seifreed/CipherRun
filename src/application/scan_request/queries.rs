use super::ScanRequest;
use crate::protocols::Protocol;
use crate::starttls::StarttlsProtocol;
use crate::utils::retry::RetryConfig;
use std::time::Duration;

impl ScanRequest {
    pub fn protocols_to_test(&self) -> Option<Vec<Protocol>> {
        let flags = [
            (self.scan.ssl2, Protocol::SSLv2),
            (self.scan.ssl3, Protocol::SSLv3),
            (self.scan.tls10, Protocol::TLS10),
            (self.scan.tls11, Protocol::TLS11),
            (self.scan.tls12, Protocol::TLS12),
            (self.scan.tls13, Protocol::TLS13),
        ];

        let selected: Vec<Protocol> = flags
            .iter()
            .filter(|(enabled, _)| *enabled)
            .map(|(_, proto)| *proto)
            .collect();

        if !selected.is_empty() {
            return Some(selected);
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
        self.scan.protocols
            || self.scan.each_cipher
            || self.scan.cipher_per_proto
            || self.scan.categories
            || self.scan.forward_secrecy
            || self.scan.server_defaults
            || self.scan.server_preference
            || self.scan.headers
            || self.scan.vulnerabilities
            || self.has_specific_vulnerability_focus()
            || self.has_explicit_fingerprint_focus()
            || self.fingerprint.client_simulation
            || self.scan.ocsp
            || self.scan.pre_handshake
            || self.scan.probe_status
            || self.scan.show_sigs
            || self.scan.show_groups
            || self.scan.show_client_cas
    }

    pub fn has_specific_vulnerability_focus(&self) -> bool {
        self.scan.heartbleed
            || self.scan.ccs
            || self.scan.ticketbleed
            || self.scan.robot
            || self.scan.renegotiation
            || self.scan.crime
            || self.scan.breach
            || self.scan.poodle
            || self.scan.fallback
            || self.scan.sweet32
            || self.scan.beast
            || self.scan.lucky13
            || self.scan.freak
            || self.scan.logjam
            || self.scan.drown
            || self.scan.early_data
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
