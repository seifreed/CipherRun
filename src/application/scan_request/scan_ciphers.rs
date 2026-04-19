#[derive(Debug, Clone, Default)]
pub struct ScanRequestCiphers {
    pub each_cipher: bool,
    pub cipher_per_proto: bool,
    pub categories: bool,
    pub forward_secrecy: bool,
    pub server_defaults: bool,
    pub server_preference: bool,
    pub no_ciphersuites: bool,
    pub show_groups: bool,
    pub no_groups: bool,
    pub show_sigs: bool,
    pub show_client_cas: bool,
}
