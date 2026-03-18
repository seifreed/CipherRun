use super::ClientHelloBuilder;
use crate::Result;
use crate::constants::VERSION_TLS_1_3;
use crate::protocols::Protocol;

const TLS13_SUPPORTED_GROUPS: &[u16] = &[
    0x001d, 0x0017, 0x001e, 0x0019, 0x0018, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
];
const LEGACY_SUPPORTED_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019];
const TLS13_SIGNATURE_ALGORITHMS: &[(u8, u8)] = &[
    (0x04, 0x03),
    (0x05, 0x03),
    (0x06, 0x03),
    (0x08, 0x07),
    (0x08, 0x08),
    (0x08, 0x09),
    (0x08, 0x0a),
    (0x08, 0x0b),
    (0x08, 0x04),
    (0x08, 0x05),
    (0x08, 0x06),
    (0x04, 0x01),
    (0x05, 0x01),
    (0x06, 0x01),
];
const LEGACY_SIGNATURE_ALGORITHMS: &[(u8, u8)] = &[
    (0x04, 0x03),
    (0x05, 0x03),
    (0x06, 0x03),
    (0x04, 0x01),
    (0x05, 0x01),
    (0x06, 0x01),
];

impl ClientHelloBuilder {
    pub fn for_vulnerability_testing(&mut self) -> &mut Self {
        self.add_ciphers(&[0xc02f, 0xc030, 0x009e, 0x009c, 0x002f, 0x0035]);
        self
    }

    pub fn for_rsa_key_exchange(&mut self) -> &mut Self {
        self.add_ciphers(&[0x002f, 0x0035, 0x009c]);
        self
    }

    pub fn for_cbc_ciphers(&mut self) -> &mut Self {
        self.add_ciphers(&[0x002f, 0x0035, 0x003c, 0x003d]);
        self
    }

    pub fn build_with_defaults(&mut self, hostname: Option<&str>) -> Result<Vec<u8>> {
        if matches!(self.protocol, Protocol::TLS13) {
            self.add_tls13_defaults(hostname);
        } else {
            self.add_legacy_defaults(hostname);
        }

        self.build()
    }

    fn add_tls13_defaults(&mut self, hostname: Option<&str>) {
        if let Some(host) = hostname {
            self.add_sni(host);
        }
        self.add_ec_point_formats();
        self.add_supported_groups(TLS13_SUPPORTED_GROUPS);
        self.add_session_ticket();
        self.add_encrypt_then_mac();
        self.add_extended_master_secret();
        self.add_status_request();
        self.add_signature_algorithms(TLS13_SIGNATURE_ALGORITHMS);
        self.add_supported_versions(&[VERSION_TLS_1_3]);
        self.add_psk_key_exchange_modes();
        self.add_key_share(0x001d);
    }

    fn add_legacy_defaults(&mut self, hostname: Option<&str>) {
        if let Some(host) = hostname {
            self.add_sni(host);
        }
        self.add_supported_groups(LEGACY_SUPPORTED_GROUPS);
        self.add_signature_algorithms(LEGACY_SIGNATURE_ALGORITHMS);
        self.add_session_ticket();
        self.add_extended_master_secret();
        self.add_renegotiation_info();
        self.add_status_request();
    }
}
