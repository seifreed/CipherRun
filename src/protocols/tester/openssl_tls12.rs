use super::ProtocolProbeOutcome;

pub(super) fn classify_handshake_error(
    error: &openssl::ssl::HandshakeError<std::net::TcpStream>,
) -> ProtocolProbeOutcome {
    use openssl::ssl::HandshakeError;

    match error {
        HandshakeError::SetupFailure(_) | HandshakeError::WouldBlock(_) => {
            ProtocolProbeOutcome::Inconclusive
        }
        HandshakeError::Failure(stream) => {
            classify_failure(stream.error().code(), &stream.error().to_string())
        }
    }
}

fn classify_failure(code: openssl::ssl::ErrorCode, details: &str) -> ProtocolProbeOutcome {
    use openssl::ssl::ErrorCode;

    match code {
        ErrorCode::SYSCALL
        | ErrorCode::ZERO_RETURN
        | ErrorCode::WANT_READ
        | ErrorCode::WANT_WRITE => ProtocolProbeOutcome::Inconclusive,
        _ if crate::utils::network::is_transport_anomaly_error(details) => {
            ProtocolProbeOutcome::Inconclusive
        }
        _ => ProtocolProbeOutcome::NotSupported,
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtocolProbeOutcome as Outcome, classify_failure, classify_handshake_error};
    use openssl::ssl::{ErrorCode, HandshakeError, SslConnector, SslMethod};
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    fn handshake_error_from_alert() -> HandshakeError<TcpStream> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[21, 3, 3, 0, 2, 2, 70]).unwrap();
        });
        let stream = TcpStream::connect(addr).unwrap();
        let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
        let error = connector
            .configure()
            .unwrap()
            .connect("localhost", stream)
            .unwrap_err();
        server.join().unwrap();
        error
    }

    #[test]
    fn setup_failures_are_inconclusive() {
        let error = HandshakeError::<TcpStream>::SetupFailure(openssl::error::ErrorStack::get());

        assert_eq!(classify_handshake_error(&error), Outcome::Inconclusive);
    }

    #[test]
    fn classifies_server_protocol_alerts() {
        let error = handshake_error_from_alert();

        assert!(matches!(&error, HandshakeError::Failure(_)));
        assert_eq!(classify_handshake_error(&error), Outcome::NotSupported);
    }

    #[test]
    fn retryable_openssl_codes_are_inconclusive() {
        for code in [
            ErrorCode::SYSCALL,
            ErrorCode::ZERO_RETURN,
            ErrorCode::WANT_READ,
            ErrorCode::WANT_WRITE,
        ] {
            assert_eq!(classify_failure(code, ""), Outcome::Inconclusive);
        }
    }

    #[test]
    fn transport_anomalies_are_inconclusive() {
        assert_eq!(
            classify_failure(ErrorCode::SSL, "unexpected eof while reading"),
            Outcome::Inconclusive
        );
    }

    #[test]
    fn protocol_alerts_are_not_supported() {
        assert_eq!(
            classify_failure(ErrorCode::SSL, "tlsv1 alert protocol version"),
            Outcome::NotSupported
        );
    }
}
