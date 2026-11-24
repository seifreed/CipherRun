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
    connector_with_resolver(hostname, &resolver).await
}

async fn connector_with_resolver(
    hostname: &str,
    resolver: &hickory_resolver::TokioResolver,
) -> Result<Option<TlsConnector>> {
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
            let client_config = client_config_with_ech(config, provider)?;

            return Ok(Some(TlsConnector::from(Arc::new(client_config))));
        }
    }

    Ok(None)
}

fn client_config_with_ech(
    config: EchConfig,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<rustls::ClientConfig> {
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_ech(EchMode::Enable(config))
        .map_err(|error| TlsError::Other(format!("ECH config setup failed: {error}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::Message;
    use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    use hickory_resolver::proto::rr::rdata::{HTTPS, SVCB};
    use hickory_resolver::proto::rr::{Name, RData, Record};
    use hickory_resolver::{TokioResolver, config::*, net::runtime::TokioRuntimeProvider};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

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

    #[tokio::test]
    async fn resolver_https_answer_builds_an_ech_connector_offline() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback DNS socket should bind");
        let port = socket.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut request = [0; 2048];
            let (len, peer) = socket.recv_from(&mut request).await.unwrap();
            let query = Message::from_vec(&request[..len]).unwrap();
            let config =
                hickory_resolver::proto::rr::rdata::svcb::EchConfigList(valid_config_list());
            let answer = Record::from_rdata(
                Name::from_ascii("ech.example").unwrap(),
                60,
                RData::HTTPS(HTTPS(SVCB::new(
                    1,
                    Name::root(),
                    vec![(
                        SvcParamKey::EchConfigList,
                        SvcParamValue::EchConfigList(config),
                    )],
                ))),
            );
            let mut response = Message::response(query.metadata.id, query.metadata.op_code);
            response
                .add_queries(query.queries.iter().cloned())
                .add_answer(answer);
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });

        let mut udp = ConnectionConfig::udp();
        udp.port = port;
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![NameServerConfig::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                false,
                vec![udp],
            )],
        );
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .expect("loopback DNS resolver should build");

        let connector = connector_with_resolver("ech.example", &resolver)
            .await
            .expect("valid HTTPS ECH answer should configure a connector");
        server.await.expect("loopback DNS server should respond");
        assert!(connector.is_some());
    }

    #[test]
    fn unsupported_tls_provider_returns_ech_setup_error() {
        let config = EchConfig::new(
            EchConfigListBytes::from(valid_config_list()),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        )
        .expect("ECH configuration should parse");
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites.clear();

        let error = client_config_with_ech(config, Arc::new(provider))
            .expect_err("provider without TLS 1.3 must reject ECH setup");

        assert!(error.to_string().contains("ECH config setup failed"));
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
