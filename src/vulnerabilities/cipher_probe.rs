//! Shared raw-handshake cipher-suite probe for vulnerability checks.
//!
//! The vendored OpenSSL build is compiled without legacy/weak ciphers (RC4,
//! 3DES, DES, export, Blowfish), so `SslContextBuilder::set_cipher_list`
//! rejects their names with "no cipher match". An OpenSSL-based probe therefore
//! reports those suites unsupported regardless of the server — a structural
//! false negative for the very weaknesses these checks exist to detect.
//!
//! Probing by wire cipher-suite ID over a raw ClientHello is unaffected by the
//! local OpenSSL cipher availability: the bytes go on the wire as-is and the
//! server's ServerHello (or alert) is the authority.

use crate::constants::{CONTENT_TYPE_ALERT, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_SERVER_HELLO};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Connect timeout for a single cipher probe.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Read timeout for a single cipher probe.
const PROBE_READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Read buffer size for the ServerHello/alert response of a probe.
const PROBE_BUFFER_SIZE: usize = 4096;

const MIN_SERVER_HELLO_LEN: usize = 43;

/// Outcome of probing a server for support of a single cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherProbeStatus {
    /// Server returned a ServerHello — the suite is supported.
    Supported,
    /// Server returned a TLS alert — the suite was conclusively rejected.
    NotSupported,
    /// No conclusive answer (no socket, transport error, truncated/non-TLS
    /// response). Never treated as a clean pass.
    Inconclusive,
}

/// Probe a single cipher suite by its wire ID across the given protocol
/// versions.
///
/// Returns `Supported` as soon as any version yields a ServerHello;
/// `NotSupported` only if at least one version conclusively rejected the suite
/// and none were inconclusive; otherwise `Inconclusive` so a transport anomaly
/// is never reported as "not vulnerable".
pub(crate) async fn probe_cipher_suite(
    target: &Target,
    hexcode: u16,
    protocols: &[Protocol],
    starttls: Option<crate::starttls::StarttlsProtocol>,
    sni_override: Option<&str>,
    starttls_hostname: Option<&str>,
) -> CipherProbeStatus {
    let mut saw_inconclusive = false;
    for &protocol in protocols {
        match probe_cipher_at_protocol(
            target,
            hexcode,
            protocol,
            starttls,
            sni_override,
            starttls_hostname,
        )
        .await
        {
            CipherProbeStatus::Supported => return CipherProbeStatus::Supported,
            CipherProbeStatus::NotSupported => {}
            CipherProbeStatus::Inconclusive => saw_inconclusive = true,
        }
    }

    if saw_inconclusive {
        CipherProbeStatus::Inconclusive
    } else {
        CipherProbeStatus::NotSupported
    }
}

/// Probe a list of named cipher suites and collect which the server supports.
///
/// Returns `(supported_names, saw_inconclusive)`. A suite is included in
/// `supported_names` only when a ServerHello confirmed it; `saw_inconclusive` is
/// set when any suite could not be classified, so callers can avoid reporting a
/// clean "not vulnerable" verdict on a transport anomaly. This is the shared
/// engine behind the weak-cipher vulnerability checks (RC4, NULL), mirroring how
/// SWEET32 and FREAK probe their suites by wire ID — necessary because the
/// vendored OpenSSL build cannot offer these legacy ciphers and the default
/// cipher enumeration deliberately excludes them.
pub(crate) async fn probe_supported_suites(
    target: &Target,
    suites: &[(u16, &str)],
    protocols: &[Protocol],
    starttls: Option<crate::starttls::StarttlsProtocol>,
    sni_override: Option<&str>,
    starttls_hostname: Option<&str>,
) -> (Vec<String>, bool) {
    let mut supported = Vec::new();
    let mut inconclusive = false;
    for (hexcode, name) in suites {
        match probe_cipher_suite(
            target,
            *hexcode,
            protocols,
            starttls,
            sni_override,
            starttls_hostname,
        )
        .await
        {
            CipherProbeStatus::Supported => supported.push((*name).to_string()),
            CipherProbeStatus::NotSupported => {}
            CipherProbeStatus::Inconclusive => inconclusive = true,
        }
    }
    (supported, inconclusive)
}

/// Send a single-cipher ClientHello at `protocol` and classify the response.
async fn probe_cipher_at_protocol(
    target: &Target,
    hexcode: u16,
    protocol: Protocol,
    starttls: Option<crate::starttls::StarttlsProtocol>,
    sni_override: Option<&str>,
    starttls_hostname: Option<&str>,
) -> CipherProbeStatus {
    let Some(addr) = target.socket_addrs().first().copied() else {
        return CipherProbeStatus::Inconclusive;
    };

    // STARTTLS negotiation hostname (e.g. XMPP stream `to=`, SMTP EHLO): honor
    // the explicit override (--xmpphost) when set, else the target hostname.
    let starttls_host = starttls_hostname.unwrap_or(target.hostname.as_str());
    let mut stream = match crate::utils::network::connect_with_starttls(
        addr,
        PROBE_CONNECT_TIMEOUT,
        starttls,
        starttls_host,
    )
    .await
    {
        Ok(s) => s,
        Err(_) => return CipherProbeStatus::Inconclusive,
    };

    let mut builder = ClientHelloBuilder::new(protocol);
    builder.add_cipher(hexcode);
    let sni = crate::utils::network::sni_hostname_for_target(&target.hostname, sni_override);
    let client_hello = match builder.build_with_defaults(sni.as_deref()) {
        Ok(hello) => hello,
        Err(_) => return CipherProbeStatus::Inconclusive,
    };

    let exchange = tokio::time::timeout(PROBE_READ_TIMEOUT, async {
        stream.write_all(&client_hello).await?;
        let mut response = vec![0u8; PROBE_BUFFER_SIZE];
        let n = stream.read(&mut response).await?;
        Ok::<_, crate::TlsError>((response, n))
    })
    .await;

    match exchange {
        Ok(Ok((response, n))) => classify_probe_response(&response, n),
        _ => CipherProbeStatus::Inconclusive,
    }
}

/// Classify a probe response: a ServerHello means the server accepted the suite
/// (`Supported`); a TLS alert means it rejected it (`NotSupported`); anything
/// else (truncated, closed, non-TLS) is `Inconclusive`.
fn classify_probe_response(response: &[u8], n: usize) -> CipherProbeStatus {
    if n >= MIN_SERVER_HELLO_LEN && response[0] == CONTENT_TYPE_HANDSHAKE {
        let record_len = u16::from_be_bytes([response[3], response[4]]) as usize;
        let handshake_len =
            u32::from_be_bytes([0, response[6], response[7], response[8]]) as usize;
        if response[5] == HANDSHAKE_TYPE_SERVER_HELLO
            && record_len + 5 <= n
            && handshake_len + 9 <= n
        {
            return CipherProbeStatus::Supported;
        }
    }

    if n >= 7 && response[0] == CONTENT_TYPE_ALERT {
        let alert_record_len = u16::from_be_bytes([response[3], response[4]]) as usize;
        if alert_record_len != 2 {
            return CipherProbeStatus::Inconclusive;
        }
        CipherProbeStatus::NotSupported
    } else {
        CipherProbeStatus::Inconclusive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_serverhello_is_supported() {
        let mut response = vec![0u8; MIN_SERVER_HELLO_LEN];
        response[0] = CONTENT_TYPE_HANDSHAKE;
        response[3] = 0x00;
        response[4] = (MIN_SERVER_HELLO_LEN - 5) as u8;
        response[5] = HANDSHAKE_TYPE_SERVER_HELLO;
        response[6] = 0x00;
        response[7] = 0x00;
        response[8] = (MIN_SERVER_HELLO_LEN - 9) as u8;
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::Supported
        );
    }

    #[test]
    fn test_classify_alert_is_not_supported() {
        let mut response = vec![0u8; 7];
        response[0] = CONTENT_TYPE_ALERT;
        response[3] = 0x00;
        response[4] = 0x02;
        response[5] = 0x02;
        response[6] = 0x46;
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::NotSupported
        );
    }

    #[test]
    fn test_classify_malformed_alert_is_inconclusive() {
        let mut response = vec![0u8; 7];
        response[0] = CONTENT_TYPE_ALERT;
        response[3] = 0x00;
        response[4] = 0x03;
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::Inconclusive
        );
    }

    #[test]
    fn test_classify_truncated_alert_is_inconclusive() {
        let response = vec![CONTENT_TYPE_ALERT, 0x03, 0x03, 0x00, 0x02, 0x02];
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::Inconclusive
        );
    }

    #[test]
    fn test_classify_handshake_without_serverhello_is_inconclusive() {
        let mut response = vec![0u8; 16];
        response[0] = CONTENT_TYPE_HANDSHAKE;
        response[5] = HANDSHAKE_TYPE_SERVER_HELLO + 1;
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::Inconclusive
        );
    }

    #[test]
    fn test_classify_truncated_serverhello_is_inconclusive() {
        let mut response = vec![0u8; 16];
        response[0] = CONTENT_TYPE_HANDSHAKE;
        response[5] = HANDSHAKE_TYPE_SERVER_HELLO;
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::Inconclusive
        );
    }

    #[test]
    fn test_classify_closed_connection_is_inconclusive() {
        assert_eq!(
            classify_probe_response(&[], 0),
            CipherProbeStatus::Inconclusive
        );
    }
}
