//! TLS client configuration that performs no server-certificate verification.
//!
//! A TLS/SSL scanner must retrieve and inspect certificates from servers whose
//! certificates are expired, self-signed, untrusted, or hostname-mismatched —
//! precisely the cases a verifying client rejects with a fatal handshake error.
//! Retrieving the chain must therefore be decoupled from trusting it; the
//! certificate validator (`certificates::validator`) performs the actual
//! security assessment on the retrieved chain afterwards.

use rustls::ClientConfig;
use std::sync::Arc;

/// Build a `ClientConfig` that accepts any server certificate without
/// verification, so the scanner can fetch chains from misconfigured servers.
///
/// This must only be used for inspection paths. It deliberately bypasses trust
/// validation — the retrieved certificate is analysed, never trusted for a
/// secure channel.
/// Ensure the rustls `ring` crypto provider is installed as the process default.
///
/// rustls 0.23 does not auto-select a crypto provider: building a `ClientConfig`
/// with the default `ClientConfig::builder()` panics with
/// "Could not automatically determine the process-level CryptoProvider" if no
/// provider has been installed. The binary installs it in `main`, but library
/// consumers (and integration tests that bypass `main`) hit the panic. Call
/// this from every config builder so the library is self-contained.
/// `install_default()` is idempotent — a no-op once a provider is installed.
pub(crate) fn ensure_ring_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn insecure_client_config() -> ClientConfig {
    ensure_ring_provider();
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth()
}

/// Like [`insecure_client_config`] but restricted to the given protocol
/// versions.
///
/// Used by client-handshake simulation, which reports the protocol/cipher a
/// client profile would negotiate independently of certificate trust (trust is
/// assessed separately by the certificate validator).
pub fn insecure_client_config_with_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
    ensure_ring_provider();
    ClientConfig::builder_with_protocol_versions(versions)
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth()
}

/// Like [`insecure_client_config`] but presenting a client certificate for
/// mutual TLS.
///
/// mTLS servers are predominantly internal/corporate endpoints fronted by
/// private or self-signed CAs — exactly the certificates a verifying client
/// rejects. The scanner must still probe protocols and retrieve the chain from
/// such hosts (trust is assessed separately by the certificate validator), so
/// server-certificate verification is deliberately bypassed here just as in the
/// non-mTLS inspection path.
pub fn insecure_client_config_with_client_auth(
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> std::result::Result<ClientConfig, rustls::Error> {
    ensure_ring_provider();
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_client_auth_cert(cert_chain, key)
}

/// Server-certificate verifier that accepts every certificate.
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::time::{Duration, SystemTime};

    #[test]
    fn accepts_arbitrary_certificate() {
        let verifier = NoCertVerifier;
        let cert = CertificateDer::from(vec![0x30, 0x00]);
        let server_name = ServerName::try_from("example.com").expect("valid name");
        let now = UnixTime::since_unix_epoch(Duration::from_secs(
            SystemTime::UNIX_EPOCH
                .elapsed()
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ));

        assert!(
            verifier
                .verify_server_cert(&cert, &[], &server_name, &[], now)
                .is_ok()
        );
    }

    #[test]
    fn builds_client_config() {
        // The process-level crypto provider is installed by the binary at
        // startup; install it here so the config builder has one in tests.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let _config = insecure_client_config();
    }
}
