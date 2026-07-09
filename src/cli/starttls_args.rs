// STARTTLS protocol configuration arguments
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use clap::Args;

/// STARTTLS protocol configuration options
///
/// This struct contains all arguments related to STARTTLS protocol selection
/// and configuration for various application protocols (SMTP, IMAP, POP3, FTP,
/// LDAP, XMPP, PostgreSQL, MySQL, IRC, etc.)
#[derive(Args, Debug, Clone, Default)]
pub struct StarttlsArgs {
    /// STARTTLS protocol (smtp, imap, pop3, ftp, xmpp, etc.)
    #[arg(short = 't', long = "starttls", value_name = "PROTOCOL")]
    pub protocol: Option<String>,

    /// STARTTLS for SMTP (ports 25, 587, 465)
    #[arg(long = "starttls-smtp")]
    pub smtp: bool,

    /// STARTTLS for IMAP (port 143)
    #[arg(long = "starttls-imap")]
    pub imap: bool,

    /// STARTTLS for POP3 (port 110)
    #[arg(long = "starttls-pop3")]
    pub pop3: bool,

    /// STARTTLS for FTP (port 21)
    #[arg(long = "starttls-ftp")]
    pub ftp: bool,

    /// STARTTLS for LDAP (port 389)
    #[arg(long = "starttls-ldap")]
    pub ldap: bool,

    /// STARTTLS for XMPP/Jabber (port 5222)
    #[arg(long = "starttls-xmpp")]
    pub xmpp: bool,

    /// STARTTLS for PostgreSQL (port 5432)
    #[arg(long = "starttls-psql")]
    pub psql: bool,

    /// STARTTLS for MySQL (port 3306)
    #[arg(long = "starttls-mysql")]
    pub mysql: bool,

    /// STARTTLS for IRC (port 6667)
    #[arg(long = "starttls-irc")]
    pub irc: bool,

    /// XMPP server-to-server mode (alternative to --starttls-xmpp)
    #[arg(long = "xmpp-server")]
    pub xmpp_server: bool,

    /// XMPP host domain (for STARTTLS XMPP)
    #[arg(long = "xmpphost", value_name = "DOMAIN")]
    pub xmpphost: Option<String>,

    /// RDP mode - send RDP preamble before TLS handshake
    #[arg(long = "rdp")]
    pub rdp: bool,

    /// NNTP STARTTLS mode
    #[arg(long = "nntp")]
    pub nntp: bool,

    /// SIEVE STARTTLS mode
    #[arg(long = "sieve")]
    pub sieve: bool,

    /// LMTP STARTTLS mode
    #[arg(long = "lmtp")]
    pub lmtp: bool,
}

impl StarttlsArgs {
    /// Detect which STARTTLS protocol is requested
    pub fn starttls_protocol(&self) -> Option<crate::starttls::StarttlsProtocol> {
        use crate::starttls::StarttlsProtocol;

        if self.smtp {
            Some(StarttlsProtocol::SMTP)
        } else if self.imap {
            Some(StarttlsProtocol::IMAP)
        } else if self.pop3 {
            Some(StarttlsProtocol::POP3)
        } else if self.ftp {
            Some(StarttlsProtocol::FTP)
        } else if self.ldap {
            Some(StarttlsProtocol::LDAP)
        } else if self.xmpp || self.xmpp_server {
            Some(StarttlsProtocol::XMPP)
        } else if self.psql {
            Some(StarttlsProtocol::POSTGRES)
        } else if self.mysql {
            Some(StarttlsProtocol::MYSQL)
        } else if self.irc {
            Some(StarttlsProtocol::IRC)
        } else if self.nntp {
            Some(StarttlsProtocol::NNTP)
        } else if self.sieve {
            Some(StarttlsProtocol::SIEVE)
        } else if self.lmtp {
            Some(StarttlsProtocol::LMTP)
        } else {
            let protocol = self.protocol.as_deref()?.trim().to_ascii_lowercase();
            match protocol.as_str() {
                "smtp" => Some(StarttlsProtocol::SMTP),
                "imap" => Some(StarttlsProtocol::IMAP),
                "pop3" => Some(StarttlsProtocol::POP3),
                "ftp" => Some(StarttlsProtocol::FTP),
                "ldap" => Some(StarttlsProtocol::LDAP),
                "xmpp" | "xmpp-server" => Some(StarttlsProtocol::XMPP),
                "postgres" | "postgresql" | "psql" => Some(StarttlsProtocol::POSTGRES),
                "mysql" => Some(StarttlsProtocol::MYSQL),
                "irc" => Some(StarttlsProtocol::IRC),
                "nntp" => Some(StarttlsProtocol::NNTP),
                "sieve" => Some(StarttlsProtocol::SIEVE),
                "lmtp" => Some(StarttlsProtocol::LMTP),
                "telnet" => Some(StarttlsProtocol::Telnet),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starttls::StarttlsProtocol;

    #[test]
    fn test_starttls_protocol_none() {
        let args = StarttlsArgs::default();
        assert!(args.starttls_protocol().is_none());
    }

    #[test]
    fn test_starttls_protocol_smtp() {
        let args = StarttlsArgs {
            smtp: true,
            ..Default::default()
        };
        assert_eq!(args.starttls_protocol(), Some(StarttlsProtocol::SMTP));
    }

    #[test]
    fn test_starttls_protocol_xmpp_server() {
        let args = StarttlsArgs {
            xmpp_server: true,
            ..Default::default()
        };
        assert_eq!(args.starttls_protocol(), Some(StarttlsProtocol::XMPP));
    }

    #[test]
    fn test_starttls_protocol_precedence() {
        let args = StarttlsArgs {
            imap: true,
            smtp: true,
            ..Default::default()
        };
        assert_eq!(args.starttls_protocol(), Some(StarttlsProtocol::SMTP));
    }

    #[test]
    fn test_starttls_args_parse_protocol_string() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(flatten)]
            args: StarttlsArgs,
        }

        let parsed = TestCli::parse_from(["test", "--starttls", "pop3"]);
        let args = parsed.args;
        assert_eq!(args.protocol.as_deref(), Some("pop3"));
        assert_eq!(args.starttls_protocol(), Some(StarttlsProtocol::POP3));
    }

    #[test]
    fn test_starttls_protocol_extended_flags() {
        assert_eq!(
            StarttlsArgs {
                nntp: true,
                ..Default::default()
            }
            .starttls_protocol(),
            Some(StarttlsProtocol::NNTP)
        );
        assert_eq!(
            StarttlsArgs {
                sieve: true,
                ..Default::default()
            }
            .starttls_protocol(),
            Some(StarttlsProtocol::SIEVE)
        );
        assert_eq!(
            StarttlsArgs {
                lmtp: true,
                ..Default::default()
            }
            .starttls_protocol(),
            Some(StarttlsProtocol::LMTP)
        );
        assert_eq!(
            StarttlsArgs {
                protocol: Some(" telnet ".to_string()),
                ..Default::default()
            }
            .starttls_protocol(),
            Some(StarttlsProtocol::Telnet)
        );
    }

    #[test]
    fn test_starttls_protocol_string_normalization() {
        let args = StarttlsArgs {
            protocol: Some(" PostgreSQL ".to_string()),
            ..Default::default()
        };
        assert_eq!(args.starttls_protocol(), Some(StarttlsProtocol::POSTGRES));
    }
}
