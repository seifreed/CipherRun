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

pub(super) fn analyze_banner(banner: &[u8]) -> (ApplicationProtocol, f64) {
    let banner_str = String::from_utf8_lossy(banner);
    let lower = banner_str.to_lowercase();

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

    if (lower.contains("<stream:stream") || lower.contains("<?xml")) && lower.contains("jabber") {
        return (ApplicationProtocol::XmppStartTls, 0.90);
    }

    // MySQL greeting: 3-byte little-endian payload length + 1-byte sequence
    // number (always 0x00 for the first server packet) + protocol version
    // (0x0a for v10) + null-terminated ASCII version string.
    //
    // S6 fix: the previous check only verified `bytes[3]==0x00 && bytes[4]==0x0a`
    // which matches any binary protocol with a nullish byte at offset 3 and
    // 0x0a at offset 4. We now also validate a plausible packet-length field
    // and that the version string at offset 5 consists of printable ASCII
    // (digits, dots, letters, hyphens) — matching real MySQL greetings like
    // "5.7.38-log" or "8.0.31".
    if banner.len() > 10 && banner[3] == 0x00 && banner[4] == 0x0a {
        let b = banner;
        let pkt_len = u32::from_le_bytes([b[0], b[1], b[2], 0]) as usize;
        let version_ok = b[5..]
            .iter()
            .take_while(|&&byte| byte != 0x00)
            .take(32)
            .all(|&byte| {
                byte.is_ascii_digit() || byte == b'.' || byte == b'-' || byte.is_ascii_alphabetic()
            });
        if pkt_len > 0 && pkt_len < 1024 && version_ok {
            return (ApplicationProtocol::Mysql, 0.95);
        }
    }

    if lower.contains("postgresql") {
        return (ApplicationProtocol::Postgres, 0.90);
    }

    if lower.starts_with("-err") || lower.starts_with("+pong") {
        return (ApplicationProtocol::Redis, 0.85);
    }

    if banner.len() > 16 && banner[0..4] == [0x3a, 0x00, 0x00, 0x00] {
        return (ApplicationProtocol::MongoDB, 0.80);
    }

    (ApplicationProtocol::Unknown, 0.0)
}

pub(super) fn extract_version(banner: &[u8], protocol: ApplicationProtocol) -> Option<String> {
    let s = std::str::from_utf8(banner).ok()?;
    match protocol {
        ApplicationProtocol::Smtp
        | ApplicationProtocol::SmtpStartTls
        | ApplicationProtocol::Imap
        | ApplicationProtocol::ImapStartTls
        | ApplicationProtocol::Pop3
        | ApplicationProtocol::Pop3StartTls
        | ApplicationProtocol::Ftp
        | ApplicationProtocol::FtpStartTls => s.lines().next().map(|l| l.to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a MySQL-shaped banner as an ASCII-safe &str (no bytes >= 0x80).
    fn mysql_banner_str(version: &str) -> String {
        let mut out = String::new();
        let payload_len = 1 + version.len() + 1; // proto + version + NUL
        out.push((payload_len & 0x7f) as u8 as char);
        out.push(0u8 as char);
        out.push(0u8 as char);
        out.push(0u8 as char); // sequence
        out.push(0x0au8 as char); // protocol v10
        out.push_str(version);
        out.push(0u8 as char);
        out.push_str("   "); // pad to >10 bytes
        out
    }

    #[test]
    fn test_mysql_detection_accepts_realistic_banner() {
        let banner = mysql_banner_str("8.0.31");
        let (proto, conf) = analyze_banner(banner.as_bytes());
        assert_eq!(proto, ApplicationProtocol::Mysql);
        assert!(conf >= 0.90);
    }

    #[test]
    fn test_mysql_detection_rejects_binary_protocol_with_incidental_bytes() {
        // S6 regression: a banner where byte[3]==0x00 and byte[4]==0x0a but
        // byte[5..] contains non-version-string bytes (BEL, bare control
        // characters) must NOT be classified as MySQL. Previously the
        // two-byte check alone would false-positive on any binary protocol
        // with a coincidental 0x00/0x0a pair.
        let mut bogus = String::new();
        bogus.push(0x05u8 as char); // payload_len[0] = 5 (plausible)
        bogus.push(0u8 as char);
        bogus.push(0u8 as char);
        bogus.push(0u8 as char); // sequence=0x00
        bogus.push(0x0au8 as char); // 0x0a at offset 4 (coincidence)
        for _ in 0..8 {
            bogus.push(0x07u8 as char); // BEL bytes — not version chars
        }
        let (proto, _conf) = analyze_banner(bogus.as_bytes());
        assert_ne!(
            proto,
            ApplicationProtocol::Mysql,
            "non-MySQL banner with coincidental header bytes must not match"
        );
    }
}
