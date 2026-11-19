//! Encrypted ClientHello (ECH) configuration discovery and TLS connector.

use crate::Result;
use crate::error::TlsError;
use crate::utils::insecure_tls::NoCertVerifier;
use hickory_resolver::proto::rr::{RData, Record, RecordType};
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

    connector_from_records(lookup.answers())
}

fn connector_from_records(records: &[Record]) -> Result<Option<TlsConnector>> {
    for record in records {
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
    use super::*;
    use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    use hickory_resolver::proto::rr::rdata::{HTTPS, SVCB};
    use hickory_resolver::proto::rr::{Name, RData, Record};

    fn https_record(params: Vec<(SvcParamKey, SvcParamValue)>) -> Record {
        Record::from_rdata(
            Name::root(),
            60,
            RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), params))),
        )
    }

    fn valid_config_list() -> Vec<u8> {
        let mut config = vec![1, 0, 0x20, 0, 0x20];
        config.extend([0x42; 32]);
        config.extend([0, 4, 0, 1, 0, 1, 0, 14]);
        config.extend(b"public.example");
        config.extend([0, 0]);

        let config_len = u16::try_from(config.len()).unwrap();
        let config_entry_len = config_len + 4;
        let mut list = config_entry_len.to_be_bytes().to_vec();
        list.extend([0xfe, 0x0d]);
        list.extend(config_len.to_be_bytes());
        list.append(&mut config);
        list
    }

    #[test]
    fn empty_config_list_is_rejected_without_network() {
        let result = rustls::client::EchConfig::new(
            rustls::pki_types::EchConfigListBytes::from(Vec::new()),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        );
        assert!(result.is_err());
    }

    #[test]
    fn records_without_ech_configuration_return_none() {
        let record = https_record(vec![(SvcParamKey::Port, SvcParamValue::Port(443))]);
        assert!(connector_from_records(&[record]).unwrap().is_none());
        assert!(connector_from_records(&[]).unwrap().is_none());

        let address = Record::from_rdata(
            Name::root(),
            60,
            RData::A(hickory_resolver::proto::rr::rdata::A(
                std::net::Ipv4Addr::LOCALHOST,
            )),
        );
        assert!(connector_from_records(&[address]).unwrap().is_none());
    }

    #[test]
    fn invalid_ech_configuration_is_reported() {
        let record = https_record(vec![(
            SvcParamKey::EchConfigList,
            SvcParamValue::EchConfigList(hickory_resolver::proto::rr::rdata::svcb::EchConfigList(
                Vec::new(),
            )),
        )]);

        assert!(connector_from_records(&[record]).is_err());
    }

    #[test]
    fn valid_ech_configuration_builds_a_connector() {
        let record = https_record(vec![(
            SvcParamKey::EchConfigList,
            SvcParamValue::EchConfigList(hickory_resolver::proto::rr::rdata::svcb::EchConfigList(
                valid_config_list(),
            )),
        )]);

        assert!(connector_from_records(&[record]).unwrap().is_some());
    }

    #[tokio::test]
    async fn invalid_hostname_is_reported_as_a_lookup_error() {
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), connector("\0"))
            .await
            .expect("invalid DNS name should fail without waiting on the network");

        assert!(result.is_err());
    }
}
