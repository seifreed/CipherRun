use super::ApplicationProtocol;

pub(super) fn protocol_from_port(port: u16) -> ApplicationProtocol {
    match port {
        21 => ApplicationProtocol::Ftp,
        22 => ApplicationProtocol::Unknown,
        25 | 587 => ApplicationProtocol::SmtpStartTls,
        80 | 8080 | 8000 => ApplicationProtocol::Http,
        110 => ApplicationProtocol::Pop3StartTls,
        143 => ApplicationProtocol::ImapStartTls,
        389 => ApplicationProtocol::LdapStartTls,
        443 | 8443 => ApplicationProtocol::Https,
        465 => ApplicationProtocol::Smtp,
        993 => ApplicationProtocol::Imap,
        995 => ApplicationProtocol::Pop3,
        3306 => ApplicationProtocol::Mysql,
        5222 => ApplicationProtocol::XmppStartTls,
        5269 => ApplicationProtocol::Xmpp,
        5432 => ApplicationProtocol::Postgres,
        6379 => ApplicationProtocol::Redis,
        27017 => ApplicationProtocol::MongoDB,
        _ => ApplicationProtocol::Unknown,
    }
}

pub(super) fn analyze_banner(banner: &str) -> (ApplicationProtocol, f64) {
    let lower = banner.to_lowercase();

    if lower.starts_with("220")
        && (lower.contains("smtp") || lower.contains("mail") || lower.contains("esmtp"))
    {
        return (ApplicationProtocol::SmtpStartTls, 0.95);
    }

    if lower.starts_with("+ok") && lower.contains("pop") {
        return (ApplicationProtocol::Pop3StartTls, 0.95);
    }

    if lower.contains("* ok") && lower.contains("imap") {
        return (ApplicationProtocol::ImapStartTls, 0.95);
    }

    if lower.starts_with("220")
        && (lower.contains("ftp") || lower.contains("filezilla") || lower.contains("proftpd"))
    {
        return (ApplicationProtocol::FtpStartTls, 0.90);
    }

    if lower.contains("<stream:stream") || lower.contains("<?xml") && lower.contains("jabber") {
        return (ApplicationProtocol::XmppStartTls, 0.90);
    }

    if banner.len() > 10 && banner.as_bytes()[4] == 0x0a {
        return (ApplicationProtocol::Mysql, 0.85);
    }

    if lower.contains("postgresql") {
        return (ApplicationProtocol::Postgres, 0.90);
    }

    if lower.starts_with("-err") || lower.starts_with("+pong") {
        return (ApplicationProtocol::Redis, 0.85);
    }

    if banner.len() > 16 && banner.as_bytes()[0..4] == [0x3a, 0x00, 0x00, 0x00] {
        return (ApplicationProtocol::MongoDB, 0.80);
    }

    (ApplicationProtocol::Unknown, 0.0)
}

pub(super) fn extract_version(banner: &str, protocol: ApplicationProtocol) -> Option<String> {
    match protocol {
        ApplicationProtocol::Smtp | ApplicationProtocol::SmtpStartTls => {
            banner.lines().next().map(|s| s.to_string())
        }
        ApplicationProtocol::Imap | ApplicationProtocol::ImapStartTls => {
            banner.lines().next().map(|s| s.to_string())
        }
        ApplicationProtocol::Pop3 | ApplicationProtocol::Pop3StartTls => {
            banner.lines().next().map(|s| s.to_string())
        }
        ApplicationProtocol::Ftp | ApplicationProtocol::FtpStartTls => {
            banner.lines().next().map(|s| s.to_string())
        }
        _ => None,
    }
}

pub(super) fn requires_starttls(protocol: ApplicationProtocol) -> bool {
    matches!(
        protocol,
        ApplicationProtocol::SmtpStartTls
            | ApplicationProtocol::ImapStartTls
            | ApplicationProtocol::Pop3StartTls
            | ApplicationProtocol::FtpStartTls
            | ApplicationProtocol::XmppStartTls
            | ApplicationProtocol::LdapStartTls
    )
}
