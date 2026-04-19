use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct ScanRequestTls {
    pub openssl_path: Option<PathBuf>,
    pub openssl_timeout: Option<u64>,
    pub ssl_native: bool,
    pub bugs: bool,
    pub local: bool,
    pub phone_out: bool,
    pub hardfail: bool,
    pub add_ca: Option<PathBuf>,
    pub sni_name: Option<String>,
    pub random_sni: bool,
    pub reverse_ptr_sni: bool,
    pub mtls_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub client_key_password: Option<String>,
    pub client_certs: Option<PathBuf>,
}
