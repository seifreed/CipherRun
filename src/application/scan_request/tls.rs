use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct ScanRequestTls {
    pub bugs: bool,
    pub phone_out: bool,
    pub hardfail: bool,
    pub sni_name: Option<String>,
    pub mtls_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub client_key_password: Option<String>,
    pub client_certs: Option<PathBuf>,
}
