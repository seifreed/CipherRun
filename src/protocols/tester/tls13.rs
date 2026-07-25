use super::ProtocolProbeOutcome;
use crate::Result;
use crate::utils::mtls::MtlsConfig;
use std::sync::Arc;
use tokio_rustls::TlsConnector;

pub(super) fn connector(mtls_config: Option<&MtlsConfig>) -> Result<TlsConnector> {
    if let Some(mtls_config) = mtls_config {
        return mtls_config.build_tls_connector();
    }

    // The scanner must detect TLS 1.3 support regardless of certificate
    // validity; certificate trust is assessed separately.
    Ok(TlsConnector::from(Arc::new(
        crate::utils::insecure_tls::insecure_client_config(),
    )))
}

pub(super) fn classify_negotiated_version(
    negotiated: Option<rustls::ProtocolVersion>,
) -> ProtocolProbeOutcome {
    // The connector advertises both TLS 1.3 and TLS 1.2, so success alone is
    // not enough to prove TLS 1.3 support.
    if negotiated == Some(rustls::ProtocolVersion::TLSv1_3) {
        ProtocolProbeOutcome::Supported
    } else {
        ProtocolProbeOutcome::NotSupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_tls13_as_supported() {
        assert_eq!(
            classify_negotiated_version(Some(rustls::ProtocolVersion::TLSv1_3)),
            ProtocolProbeOutcome::Supported
        );
    }

    #[test]
    fn classifies_other_negotiated_versions_as_not_supported() {
        assert_eq!(
            classify_negotiated_version(Some(rustls::ProtocolVersion::TLSv1_2)),
            ProtocolProbeOutcome::NotSupported
        );
        assert_eq!(
            classify_negotiated_version(None),
            ProtocolProbeOutcome::NotSupported
        );
    }
}
