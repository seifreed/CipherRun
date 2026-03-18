use serde::{Deserialize, Serialize};

/// Detected protocol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedProtocol {
    pub protocol: ApplicationProtocol,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub requires_starttls: bool,
    pub confidence: f64,
}

/// Application layer protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplicationProtocol {
    Http,
    Https,
    Smtp,
    SmtpStartTls,
    Imap,
    ImapStartTls,
    Pop3,
    Pop3StartTls,
    Ftp,
    FtpStartTls,
    Xmpp,
    XmppStartTls,
    Ldap,
    LdapStartTls,
    Mysql,
    Postgres,
    Redis,
    MongoDB,
    Unknown,
}

impl ApplicationProtocol {
    pub fn name(&self) -> &'static str {
        match self {
            ApplicationProtocol::Http => "HTTP",
            ApplicationProtocol::Https => "HTTPS",
            ApplicationProtocol::Smtp => "SMTP",
            ApplicationProtocol::SmtpStartTls => "SMTP+STARTTLS",
            ApplicationProtocol::Imap => "IMAP",
            ApplicationProtocol::ImapStartTls => "IMAP+STARTTLS",
            ApplicationProtocol::Pop3 => "POP3",
            ApplicationProtocol::Pop3StartTls => "POP3+STARTTLS",
            ApplicationProtocol::Ftp => "FTP",
            ApplicationProtocol::FtpStartTls => "FTP+STARTTLS",
            ApplicationProtocol::Xmpp => "XMPP",
            ApplicationProtocol::XmppStartTls => "XMPP+STARTTLS",
            ApplicationProtocol::Ldap => "LDAP",
            ApplicationProtocol::LdapStartTls => "LDAP+STARTTLS",
            ApplicationProtocol::Mysql => "MySQL",
            ApplicationProtocol::Postgres => "PostgreSQL",
            ApplicationProtocol::Redis => "Redis",
            ApplicationProtocol::MongoDB => "MongoDB",
            ApplicationProtocol::Unknown => "Unknown",
        }
    }

    pub fn default_port(&self) -> Option<u16> {
        match self {
            ApplicationProtocol::Http => Some(80),
            ApplicationProtocol::Https => Some(443),
            ApplicationProtocol::Smtp | ApplicationProtocol::SmtpStartTls => Some(25),
            ApplicationProtocol::Imap | ApplicationProtocol::ImapStartTls => Some(143),
            ApplicationProtocol::Pop3 | ApplicationProtocol::Pop3StartTls => Some(110),
            ApplicationProtocol::Ftp | ApplicationProtocol::FtpStartTls => Some(21),
            ApplicationProtocol::Xmpp | ApplicationProtocol::XmppStartTls => Some(5222),
            ApplicationProtocol::Ldap | ApplicationProtocol::LdapStartTls => Some(389),
            ApplicationProtocol::Mysql => Some(3306),
            ApplicationProtocol::Postgres => Some(5432),
            ApplicationProtocol::Redis => Some(6379),
            ApplicationProtocol::MongoDB => Some(27017),
            ApplicationProtocol::Unknown => None,
        }
    }
}
