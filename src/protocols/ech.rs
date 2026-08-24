//! Encrypted ClientHello (ECH) configuration discovery and TLS connector.

use crate::Result;
use crate::error::TlsError;
use crate::utils::insecure_tls::NoCertVerifier;
use hickory_resolver::proto::rr::{RData, RecordType};
use rustls::client::{EchConfig, EchMode};
use rustls::pki_types::EchConfigListBytes;
use std::sync::Arc;
use tokio_rustls::TlsConnector;

/// Build a TLS connector configured for ECH from the target's HTTPS record.
///
/// `None` means the target published no usable ECH configuration. Callers must
/// report that as inconclusive when ECH was explicitly requested.
pub async fn connector(hostname: &str) -> Result<Option<TlsConnector>> {
    let resolver = crate::utils::network::build_system_resolver()?;
    let lookup = resolver
        .lookup(hostname, RecordType::HTTPS)
        .await
        .map_err(|error| TlsError::Other(format!("ECH HTTPS lookup failed: {error}")))?;

    for record in lookup.answers() {
        let RData::HTTPS(https) = &record.data else {
            continue;
        };

        for (_, value) in &https.svc_params {
            let hickory_resolver::proto::rr::rdata::svcb::SvcParamValue::EchConfigList(ech) = value
            else {
                continue;
            };

            let config = EchConfig::new(
                EchConfigListBytes::from(ech.0.clone()),
                rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
            )
            .map_err(|error| TlsError::Other(format!("invalid ECH configuration: {error}")))?;

            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let client_config = rustls::ClientConfig::builder_with_provider(provider)
                .with_ech(EchMode::Enable(config))
                .map_err(|error| TlsError::Other(format!("ECH config setup failed: {error}")))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
                .with_no_client_auth();

            return Ok(Some(TlsConnector::from(Arc::new(client_config))));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty_config_list_is_rejected_without_network() {
        let result = rustls::client::EchConfig::new(
            rustls::pki_types::EchConfigListBytes::from(Vec::new()),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        );
        assert!(result.is_err());
    }
}
