use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ScanRequestFingerprint {
    pub ja3: bool,
    pub explicit_ja3: bool,
    pub client_hello: bool,
    pub ja3_database: Option<PathBuf>,
    pub ja3s: bool,
    pub explicit_ja3s: bool,
    pub server_hello: bool,
    pub ja3s_database: Option<PathBuf>,
    pub jarm: bool,
    pub explicit_jarm: bool,
    pub jarm_database: Option<PathBuf>,
    pub client_simulation: bool,
}

impl Default for ScanRequestFingerprint {
    fn default() -> Self {
        Self {
            ja3: true,
            explicit_ja3: false,
            client_hello: false,
            ja3_database: None,
            ja3s: true,
            explicit_ja3s: false,
            server_hello: false,
            ja3s_database: None,
            jarm: true,
            explicit_jarm: false,
            jarm_database: None,
            client_simulation: false,
        }
    }
}
