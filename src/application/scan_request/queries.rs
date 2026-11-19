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
            (self.scan.proto.quic, Protocol::QUIC),
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
                "telnet" => Some(23),
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
            || self.scan.vulns.starttls_injection
            || self.scan.vulns.sweet32
            || self.scan.vulns.beast
            || self.scan.vulns.lucky13
            || self.scan.vulns.freak
            || self.scan.vulns.logjam
            || self.scan.vulns.drown
            || self.scan.vulns.early_data
            || self.scan.vulns.grease
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

    #[test]
    fn protocols_to_test_prefers_explicit_flags_then_tls_all() {
        let request = ScanRequest::default();
        assert_eq!(request.protocols_to_test(), None);

        let request = ScanRequest {
            scan: crate::application::scan_request::ScanRequestScan {
                proto: crate::application::scan_request::ScanRequestProto {
                    tlsall: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            request.protocols_to_test(),
            Some(vec![
                Protocol::TLS10,
                Protocol::TLS11,
                Protocol::TLS12,
                Protocol::TLS13
            ])
        );

        let request = ScanRequest {
            scan: crate::application::scan_request::ScanRequestScan {
                proto: crate::application::scan_request::ScanRequestProto {
                    ssl2: true,
                    ssl3: true,
                    tls10: true,
                    tls11: true,
                    tls12: true,
                    tls13: true,
                    quic: true,
                    tlsall: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            request.protocols_to_test(),
            Some(vec![
                Protocol::SSLv2,
                Protocol::SSLv3,
                Protocol::TLS10,
                Protocol::TLS11,
                Protocol::TLS12,
                Protocol::TLS13,
                Protocol::QUIC
            ])
        );
    }

    #[test]
    fn starttls_boolean_options_map_to_protocol_and_default_port() {
        let options: [(fn(&mut ScanRequest), StarttlsProtocol, u16); 13] = [
            (|r| r.starttls.smtp = true, StarttlsProtocol::SMTP, 25),
            (|r| r.starttls.imap = true, StarttlsProtocol::IMAP, 143),
            (|r| r.starttls.pop3 = true, StarttlsProtocol::POP3, 110),
            (|r| r.starttls.ftp = true, StarttlsProtocol::FTP, 21),
            (|r| r.starttls.ldap = true, StarttlsProtocol::LDAP, 389),
            (|r| r.starttls.xmpp = true, StarttlsProtocol::XMPP, 5222),
            (|r| r.starttls.psql = true, StarttlsProtocol::POSTGRES, 5432),
            (|r| r.starttls.mysql = true, StarttlsProtocol::MYSQL, 3306),
            (|r| r.starttls.irc = true, StarttlsProtocol::IRC, 6667),
            (
                |r| r.starttls.xmpp_server = true,
                StarttlsProtocol::XMPP,
                5269,
            ),
            (|r| r.starttls.nntp = true, StarttlsProtocol::NNTP, 119),
            (|r| r.starttls.sieve = true, StarttlsProtocol::SIEVE, 4190),
            (|r| r.starttls.lmtp = true, StarttlsProtocol::LMTP, 24),
        ];

        for (set, expected_protocol, expected_port) in options {
            let mut request = ScanRequest::default();
            set(&mut request);
            assert_eq!(request.starttls_protocol(), Some(expected_protocol));
            assert_eq!(request.starttls_port(), Some(expected_port));
            assert!(request.has_starttls_negotiation_request());
        }

        let request = ScanRequest {
            starttls: crate::application::scan_request::ScanRequestStarttls {
                smtp: true,
                imap: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(request.starttls_protocol(), Some(StarttlsProtocol::SMTP));
        assert_eq!(request.starttls_port(), Some(25));
    }

    #[test]
    fn starttls_protocol_aliases_map_to_protocol_and_port() {
        let aliases = [
            ("smtp", StarttlsProtocol::SMTP, 25),
            ("imap", StarttlsProtocol::IMAP, 143),
            ("pop3", StarttlsProtocol::POP3, 110),
            ("ftp", StarttlsProtocol::FTP, 21),
            ("ldap", StarttlsProtocol::LDAP, 389),
            ("xmpp", StarttlsProtocol::XMPP, 5222),
            ("xmpp-server", StarttlsProtocol::XMPP, 5269),
            ("postgres", StarttlsProtocol::POSTGRES, 5432),
            ("postgresql", StarttlsProtocol::POSTGRES, 5432),
            ("psql", StarttlsProtocol::POSTGRES, 5432),
            ("mysql", StarttlsProtocol::MYSQL, 3306),
            ("irc", StarttlsProtocol::IRC, 6667),
            ("nntp", StarttlsProtocol::NNTP, 119),
            ("sieve", StarttlsProtocol::SIEVE, 4190),
            ("lmtp", StarttlsProtocol::LMTP, 24),
            ("telnet", StarttlsProtocol::Telnet, 23),
        ];

        for (alias, expected_protocol, expected_port) in aliases {
            let request = ScanRequest {
                starttls: crate::application::scan_request::ScanRequestStarttls {
                    protocol: Some(format!(" {} ", alias.to_ascii_uppercase())),
                    ..Default::default()
                },
                ..Default::default()
            };
            assert_eq!(
                request.starttls_protocol(),
                Some(expected_protocol),
                "{alias}"
            );
            assert_eq!(request.starttls_port(), Some(expected_port), "{alias}");
            assert_eq!(
                request.starttls_server_mode(),
                alias == "xmpp-server",
                "{alias}"
            );
        }

        let unknown = ScanRequest {
            starttls: crate::application::scan_request::ScanRequestStarttls {
                protocol: Some("unknown".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(unknown.starttls_protocol(), None);
        assert_eq!(unknown.starttls_port(), None);
        assert!(unknown.has_starttls_negotiation_request());
        assert!(!unknown.starttls_server_mode());
    }

    #[test]
    fn scan_focus_detects_each_significant_option() {
        assert!(!ScanRequest::default().has_specific_scan_focus());

        let focus_options: [fn(&mut ScanRequest); 22] = [
            |r| r.scan.proto.enabled = true,
            |r| r.scan.ciphers.each_cipher = true,
            |r| r.scan.ciphers.cipher_per_proto = true,
            |r| r.scan.ciphers.categories = true,
            |r| r.scan.ciphers.forward_secrecy = true,
            |r| r.scan.ciphers.server_defaults = true,
            |r| r.scan.ciphers.server_preference = true,
            |r| r.scan.prefs.headers = true,
            |r| r.scan.vulns.vulnerabilities = true,
            |r| r.scan.certs.analyze_certificates = true,
            |r| r.scan.vulns.heartbleed = true,
            |r| r.fingerprint.explicit_ja3 = true,
            |r| r.fingerprint.explicit_ja3s = true,
            |r| r.fingerprint.explicit_jarm = true,
            |r| r.fingerprint.client_simulation = true,
            |r| r.scan.certs.ocsp = true,
            |r| r.scan.prefs.pre_handshake = true,
            |r| r.scan.prefs.probe_status = true,
            |r| r.scan.ciphers.show_sigs = true,
            |r| r.scan.ciphers.show_groups = true,
            |r| r.scan.ciphers.show_client_cas = true,
            |r| r.scan.proto.quic = true,
        ];
        for set_focus in focus_options {
            let mut request = ScanRequest::default();
            set_focus(&mut request);
            assert!(request.has_specific_scan_focus());
        }

        let vulnerability_options: [fn(&mut ScanRequest); 18] = [
            |r| r.scan.vulns.heartbleed = true,
            |r| r.scan.vulns.ccs = true,
            |r| r.scan.vulns.ticketbleed = true,
            |r| r.scan.vulns.robot = true,
            |r| r.scan.vulns.renegotiation = true,
            |r| r.scan.vulns.crime = true,
            |r| r.scan.vulns.breach = true,
            |r| r.scan.vulns.poodle = true,
            |r| r.scan.vulns.fallback = true,
            |r| r.scan.vulns.starttls_injection = true,
            |r| r.scan.vulns.sweet32 = true,
            |r| r.scan.vulns.beast = true,
            |r| r.scan.vulns.lucky13 = true,
            |r| r.scan.vulns.freak = true,
            |r| r.scan.vulns.logjam = true,
            |r| r.scan.vulns.drown = true,
            |r| r.scan.vulns.early_data = true,
            |r| r.scan.vulns.grease = true,
        ];
        for set_vulnerability in vulnerability_options {
            let mut request = ScanRequest::default();
            set_vulnerability(&mut request);
            assert!(request.has_specific_vulnerability_focus());
            assert!(request.has_specific_scan_focus());
        }
    }

    #[test]
    fn retry_configuration_respects_disabled_and_zero_retry_options() {
        let request = ScanRequest::default();
        assert!(request.retry_config().is_some());

        let request = ScanRequest {
            connection: crate::application::scan_request::ScanRequestConnection {
                no_retry: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(request.retry_config().is_none());

        let request = ScanRequest {
            connection: crate::application::scan_request::ScanRequestConnection {
                max_retries: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(request.retry_config().is_none());
    }
}
