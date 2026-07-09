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

use crate::constants::{
    BUFFER_SIZE_MAX_WITH_OVERHEAD, CONTENT_TYPE_ALERT, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_SERVER_HELLO, TLS_RECORD_HEADER_SIZE,
};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::utils::network::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Connect timeout for a single cipher probe.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Read timeout for a single cipher probe.
const PROBE_READ_TIMEOUT: Duration = Duration::from_secs(3);

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
        false,
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
        let mut header = [0u8; 5];
        if stream.read_exact(&mut header).await.is_err() {
            return Ok::<_, crate::TlsError>((Vec::new(), 0));
        }

        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let total_len = TLS_RECORD_HEADER_SIZE
            .checked_add(record_len)
            .ok_or_else(|| crate::TlsError::ParseError {
                message: "Cipher probe record length overflow".to_string(),
            })?;
        if total_len > BUFFER_SIZE_MAX_WITH_OVERHEAD {
            return Ok::<_, crate::TlsError>((Vec::new(), 0));
        }

        let mut response = vec![0u8; total_len];
        response[..TLS_RECORD_HEADER_SIZE].copy_from_slice(&header);
        if stream
            .read_exact(&mut response[TLS_RECORD_HEADER_SIZE..])
            .await
            .is_err()
        {
            return Ok::<_, crate::TlsError>((Vec::new(), 0));
        }
        Ok::<_, crate::TlsError>((response, total_len))
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
    let Some(response) = response.get(..n) else {
        return CipherProbeStatus::Inconclusive;
    };

    if n >= MIN_SERVER_HELLO_LEN && response.first() == Some(&CONTENT_TYPE_HANDSHAKE) {
        let Some(record_len) = response
            .get(3..5)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
        else {
            return CipherProbeStatus::Inconclusive;
        };
        let Some(handshake_len) = response
            .get(6..9)
            .and_then(|bytes| <&[u8; 3]>::try_from(bytes).ok())
            .map(|bytes| {
                let [high, mid, low] = *bytes;
                u32::from_be_bytes([0, high, mid, low]) as usize
            })
        else {
            return CipherProbeStatus::Inconclusive;
        };
        let record_end = record_len + 5;
        if response.get(5) == Some(&HANDSHAKE_TYPE_SERVER_HELLO)
            && record_end <= n
            && handshake_len + 9 <= record_end
        {
            return CipherProbeStatus::Supported;
        }
    }

    if n >= 7 && response.first() == Some(&CONTENT_TYPE_ALERT) {
        let Some(alert_record_len) = response
            .get(3..5)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
        else {
            return CipherProbeStatus::Inconclusive;
        };
        if alert_record_len != 2 {
            return CipherProbeStatus::Inconclusive;
        }
        if n != 5 + alert_record_len {
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
    use crate::constants::BUFFER_SIZE_DEFAULT;
    use crate::utils::network::Target;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn set_byte(response: &mut [u8], offset: usize, value: u8) {
        *response
            .get_mut(offset)
            .expect("test response should contain byte offset") = value;
    }

    fn set_u16_be(response: &mut [u8], offset: usize, value: u16) {
        response
            .get_mut(offset..offset + 2)
            .expect("test response should contain u16 offset")
            .copy_from_slice(&value.to_be_bytes());
    }

    fn set_u24_be(response: &mut [u8], offset: usize, value: usize) {
        response
            .get_mut(offset..offset + 3)
            .expect("test response should contain u24 offset")
            .copy_from_slice(&[
                ((value >> 16) & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
                (value & 0xff) as u8,
            ]);
    }

    fn server_hello_record(protocol: Protocol) -> Vec<u8> {
        let mut response = vec![0u8; MIN_SERVER_HELLO_LEN];
        set_byte(&mut response, 0, CONTENT_TYPE_HANDSHAKE);
        set_u16_be(&mut response, 3, (MIN_SERVER_HELLO_LEN - 5) as u16);
        set_byte(&mut response, 5, HANDSHAKE_TYPE_SERVER_HELLO);
        set_u24_be(&mut response, 6, MIN_SERVER_HELLO_LEN - 9);
        set_u16_be(&mut response, 9, protocol.as_hex());
        response
    }

    fn large_server_hello_record(protocol: Protocol) -> Vec<u8> {
        let mut response = vec![0u8; TLS_RECORD_HEADER_SIZE + BUFFER_SIZE_DEFAULT];
        set_byte(&mut response, 0, CONTENT_TYPE_HANDSHAKE);
        set_u16_be(&mut response, 3, BUFFER_SIZE_DEFAULT as u16);
        set_byte(&mut response, 5, HANDSHAKE_TYPE_SERVER_HELLO);
        set_u24_be(&mut response, 6, MIN_SERVER_HELLO_LEN - 9);
        set_u16_be(&mut response, 9, protocol.as_hex());
        response
    }

    #[test]
    fn test_classify_serverhello_is_supported() {
        let mut response = vec![0u8; MIN_SERVER_HELLO_LEN];
        set_byte(&mut response, 0, CONTENT_TYPE_HANDSHAKE);
        set_u16_be(&mut response, 3, (MIN_SERVER_HELLO_LEN - 5) as u16);
        set_byte(&mut response, 5, HANDSHAKE_TYPE_SERVER_HELLO);
        set_u24_be(&mut response, 6, MIN_SERVER_HELLO_LEN - 9);
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::Supported
        );
    }

    #[test]
    fn test_classify_alert_is_not_supported() {
        let mut response = vec![0u8; 7];
        set_byte(&mut response, 0, CONTENT_TYPE_ALERT);
        set_u16_be(&mut response, 3, 2);
        set_byte(&mut response, 5, 0x02);
        set_byte(&mut response, 6, 0x46);
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::NotSupported
        );
    }

    #[test]
    fn test_classify_alert_with_trailing_bytes_is_inconclusive() {
        let response = vec![CONTENT_TYPE_ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46, 0x00];
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::Inconclusive
        );
    }

    #[test]
    fn test_classify_malformed_alert_is_inconclusive() {
        let mut response = vec![0u8; 7];
        set_byte(&mut response, 0, CONTENT_TYPE_ALERT);
        set_u16_be(&mut response, 3, 3);
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
        set_byte(&mut response, 0, CONTENT_TYPE_HANDSHAKE);
        set_byte(&mut response, 5, HANDSHAKE_TYPE_SERVER_HELLO + 1);
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::Inconclusive
        );
    }

    #[test]
    fn test_classify_truncated_serverhello_is_inconclusive() {
        let mut response = vec![0u8; 16];
        set_byte(&mut response, 0, CONTENT_TYPE_HANDSHAKE);
        set_byte(&mut response, 5, HANDSHAKE_TYPE_SERVER_HELLO);
        assert_eq!(
            classify_probe_response(&response, response.len()),
            CipherProbeStatus::Inconclusive
        );
    }

    #[test]
    fn test_classify_serverhello_rejects_handshake_length_past_record() {
        let mut response = vec![0u8; MIN_SERVER_HELLO_LEN + 32];
        set_byte(&mut response, 0, CONTENT_TYPE_HANDSHAKE);
        set_u16_be(&mut response, 3, (MIN_SERVER_HELLO_LEN - 5) as u16);
        set_byte(&mut response, 5, HANDSHAKE_TYPE_SERVER_HELLO);
        set_u24_be(&mut response, 6, MIN_SERVER_HELLO_LEN);
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

    #[tokio::test]
    async fn test_probe_cipher_at_protocol_reads_fragmented_serverhello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();

            let response = server_hello_record(Protocol::TLS12);
            let split = 6;
            socket.write_all(&response[..split]).await.unwrap();
            socket.write_all(&response[split..]).await.unwrap();
        });

        let target =
            Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()]).unwrap();

        let status =
            probe_cipher_at_protocol(&target, 0x1301, Protocol::TLS12, None, None, None).await;

        assert_eq!(status, CipherProbeStatus::Supported);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_probe_cipher_at_protocol_accepts_large_serverhello_record() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();

            let response = large_server_hello_record(Protocol::TLS12);
            socket.write_all(&response).await.unwrap();
        });

        let target =
            Target::with_ips("example.test".to_string(), addr.port(), vec![addr.ip()]).unwrap();

        let status =
            probe_cipher_at_protocol(&target, 0x1301, Protocol::TLS12, None, None, None).await;

        assert_eq!(status, CipherProbeStatus::Supported);
        server.await.unwrap();
    }
}
