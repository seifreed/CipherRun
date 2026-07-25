use super::ProtocolProbeOutcome;

pub(super) fn classify_handshake_error(
    error: &openssl::ssl::HandshakeError<std::net::TcpStream>,
) -> ProtocolProbeOutcome {
    use openssl::ssl::{ErrorCode, HandshakeError};

    match error {
        HandshakeError::SetupFailure(_) | HandshakeError::WouldBlock(_) => {
            ProtocolProbeOutcome::Inconclusive
        }
        HandshakeError::Failure(stream) => match stream.error().code() {
            ErrorCode::SYSCALL
            | ErrorCode::ZERO_RETURN
            | ErrorCode::WANT_READ
            | ErrorCode::WANT_WRITE => ProtocolProbeOutcome::Inconclusive,
            _ => {
                if crate::utils::network::is_transport_anomaly_error(&stream.error().to_string()) {
                    ProtocolProbeOutcome::Inconclusive
                } else {
                    ProtocolProbeOutcome::NotSupported
                }
            }
        },
    }
}

pub(super) fn hostname_and_sni(
    target_hostname: &str,
    override_hostname: Option<&str>,
) -> (String, bool) {
    let sni_hostname =
        crate::utils::network::sni_hostname_for_target(target_hostname, override_hostname);
    let hostname = sni_hostname
        .clone()
        .unwrap_or_else(|| target_hostname.to_string());
    (hostname, sni_hostname.is_some())
}
