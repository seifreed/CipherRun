// STARTTLS module - STARTTLS protocol support

pub mod ftp;
pub mod imap;
pub mod irc;
pub mod ldap;
pub mod lmtp;
pub mod mysql;
pub mod nntp;
pub mod pop3;
pub mod postgres;
pub mod protocols;
pub mod response;
pub mod sieve;
pub mod smtp;
pub mod telnet;
pub mod tester;
pub mod text_protocol;
pub mod xmpp;

pub use protocols::{StarttlsNegotiator, StarttlsProtocol, StarttlsTestResult};
pub use tester::StarttlsTester;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starttls_protocol_defaults() {
        assert_eq!(StarttlsProtocol::SMTP.default_port(), 25);
        assert!(StarttlsProtocol::SMTPS.is_implicit_tls());
        assert!(!StarttlsProtocol::SMTP.is_implicit_tls());
    }

    #[test]
    fn test_starttls_protocol_display() {
        assert_eq!(StarttlsProtocol::SMTP.to_string(), "SMTP");
        assert_eq!(StarttlsProtocol::LDAP.to_string(), "LDAP");
    }

    #[test]
    fn test_starttls_protocol_ports_additional() {
        assert_eq!(StarttlsProtocol::IMAPS.default_port(), 993);
        assert!(StarttlsProtocol::POP3S.is_implicit_tls());
    }
}
