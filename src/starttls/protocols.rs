// STARTTLS Protocol Definitions and Trait

use crate::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// STARTTLS protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StarttlsProtocol {
    SMTP,
    SMTPS,
    POP3,
    POP3S,
    IMAP,
    IMAPS,
    FTP,
    FTPS,
    XMPP,
    XMPPS,
    LDAP,
    LDAPS,
    IRC,
    IRCS,
    POSTGRES,
    MYSQL,
    NNTP,
    NNTPS,
    SIEVE,
    LMTP,
    Telnet,
}

impl StarttlsProtocol {
    /// Get default port for protocol
    pub fn default_port(&self) -> u16 {
        match self {
            StarttlsProtocol::SMTP => 25,
            StarttlsProtocol::SMTPS => 465,
            StarttlsProtocol::POP3 => 110,
            StarttlsProtocol::POP3S => 995,
            StarttlsProtocol::IMAP => 143,
            StarttlsProtocol::IMAPS => 993,
            StarttlsProtocol::FTP => 21,
            StarttlsProtocol::FTPS => 990,
            StarttlsProtocol::XMPP => 5222,
            StarttlsProtocol::XMPPS => 5223,
            StarttlsProtocol::LDAP => 389,
            StarttlsProtocol::LDAPS => 636,
            StarttlsProtocol::IRC => 6667,
            StarttlsProtocol::IRCS => 6697,
            StarttlsProtocol::POSTGRES => 5432,
            StarttlsProtocol::MYSQL => 3306,
            StarttlsProtocol::NNTP => 119,
            StarttlsProtocol::NNTPS => 563,
            StarttlsProtocol::SIEVE => 4190,
            StarttlsProtocol::LMTP => 24,
            StarttlsProtocol::Telnet => 23,
        }
    }

    /// Check if protocol uses implicit TLS (no STARTTLS negotiation)
    pub fn is_implicit_tls(&self) -> bool {
        matches!(
            self,
            StarttlsProtocol::SMTPS
                | StarttlsProtocol::POP3S
                | StarttlsProtocol::IMAPS
                | StarttlsProtocol::FTPS
                | StarttlsProtocol::XMPPS
                | StarttlsProtocol::LDAPS
                | StarttlsProtocol::IRCS
                | StarttlsProtocol::NNTPS
        )
    }

    /// Get protocol name
    pub fn name(&self) -> &'static str {
        match self {
            StarttlsProtocol::SMTP => "SMTP",
            StarttlsProtocol::SMTPS => "SMTPS",
            StarttlsProtocol::POP3 => "POP3",
            StarttlsProtocol::POP3S => "POP3S",
            StarttlsProtocol::IMAP => "IMAP",
            StarttlsProtocol::IMAPS => "IMAPS",
            StarttlsProtocol::FTP => "FTP",
            StarttlsProtocol::FTPS => "FTPS",
            StarttlsProtocol::XMPP => "XMPP",
            StarttlsProtocol::XMPPS => "XMPPS",
            StarttlsProtocol::LDAP => "LDAP",
            StarttlsProtocol::LDAPS => "LDAPS",
            StarttlsProtocol::IRC => "IRC",
            StarttlsProtocol::IRCS => "IRCS",
            StarttlsProtocol::POSTGRES => "PostgreSQL",
            StarttlsProtocol::MYSQL => "MySQL",
            StarttlsProtocol::NNTP => "NNTP",
            StarttlsProtocol::NNTPS => "NNTPS",
            StarttlsProtocol::SIEVE => "SIEVE",
            StarttlsProtocol::LMTP => "LMTP",
            StarttlsProtocol::Telnet => "Telnet",
        }
    }
}

impl std::fmt::Display for StarttlsProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// STARTTLS negotiation trait
#[async_trait]
pub trait StarttlsNegotiator: Send + Sync {
    /// Negotiate STARTTLS on the connection
    /// Returns Ok(()) if STARTTLS was successfully negotiated
    async fn negotiate_starttls(&self, stream: &mut TcpStream) -> Result<()>;

    /// Get the protocol type
    fn protocol(&self) -> StarttlsProtocol;

    /// Get the expected server greeting (for validation)
    fn expected_greeting(&self) -> Option<&str> {
        None
    }
}

use tokio::net::TcpStream;

/// Get a negotiator instance for the given protocol and hostname
pub fn get_negotiator(protocol: StarttlsProtocol, hostname: String) -> Box<dyn StarttlsNegotiator> {
    match protocol {
        StarttlsProtocol::SMTP => {
            Box::new(crate::starttls::smtp::SmtpNegotiator::new(hostname.clone()))
        }
        StarttlsProtocol::SMTPS => {
            Box::new(crate::starttls::smtp::SmtpNegotiator::new(hostname.clone()))
        }
        StarttlsProtocol::IMAP => Box::new(crate::starttls::imap::ImapNegotiator::new()),
        StarttlsProtocol::IMAPS => Box::new(crate::starttls::imap::ImapNegotiator::new()),
        StarttlsProtocol::POP3 => Box::new(crate::starttls::pop3::Pop3Negotiator::new()),
        StarttlsProtocol::POP3S => Box::new(crate::starttls::pop3::Pop3Negotiator::new()),
        StarttlsProtocol::FTP => Box::new(crate::starttls::ftp::FtpNegotiator::new()),
        StarttlsProtocol::FTPS => Box::new(crate::starttls::ftp::FtpNegotiator::new()),
        StarttlsProtocol::LDAP => Box::new(crate::starttls::ldap::LdapNegotiator::new()),
        StarttlsProtocol::LDAPS => Box::new(crate::starttls::ldap::LdapNegotiator::new()),
        StarttlsProtocol::XMPP => {
            Box::new(crate::starttls::xmpp::XmppNegotiator::new(hostname.clone()))
        }
        StarttlsProtocol::XMPPS => {
            Box::new(crate::starttls::xmpp::XmppNegotiator::new(hostname.clone()))
        }
        StarttlsProtocol::POSTGRES => {
            Box::new(crate::starttls::postgres::PostgresNegotiator::new())
        }
        StarttlsProtocol::MYSQL => Box::new(crate::starttls::mysql::MysqlNegotiator::new()),
        StarttlsProtocol::IRC => Box::new(crate::starttls::irc::IrcNegotiator::new()),
        StarttlsProtocol::IRCS => Box::new(crate::starttls::irc::IrcNegotiator::new()),
        StarttlsProtocol::NNTP => Box::new(crate::starttls::nntp::NntpNegotiator::new()),
        StarttlsProtocol::NNTPS => Box::new(crate::starttls::nntp::NntpNegotiator::new()),
        StarttlsProtocol::SIEVE => Box::new(crate::starttls::sieve::SieveNegotiator::new()),
        StarttlsProtocol::LMTP => {
            Box::new(crate::starttls::lmtp::LmtpNegotiator::new(hostname.clone()))
        }
        StarttlsProtocol::Telnet => Box::new(crate::starttls::telnet::TelnetNegotiator::new()),
    }
}

/// STARTTLS test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarttlsTestResult {
    pub protocol: StarttlsProtocol,
    pub port: u16,
    pub starttls_supported: bool,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ports() {
        assert_eq!(StarttlsProtocol::SMTP.default_port(), 25);
        assert_eq!(StarttlsProtocol::SMTPS.default_port(), 465);
        assert_eq!(StarttlsProtocol::IMAP.default_port(), 143);
        assert_eq!(StarttlsProtocol::IMAPS.default_port(), 993);
    }

    #[test]
    fn test_implicit_tls() {
        assert!(!StarttlsProtocol::SMTP.is_implicit_tls());
        assert!(StarttlsProtocol::SMTPS.is_implicit_tls());
        assert!(!StarttlsProtocol::IMAP.is_implicit_tls());
        assert!(StarttlsProtocol::IMAPS.is_implicit_tls());
    }

    #[test]
    fn test_protocol_names() {
        assert_eq!(StarttlsProtocol::SMTP.name(), "SMTP");
        assert_eq!(StarttlsProtocol::POSTGRES.name(), "PostgreSQL");
    }
}
