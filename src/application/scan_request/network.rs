#[derive(Debug, Clone)]
pub struct ScanRequestNetwork {
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub proxy: Option<String>,
    pub resolvers: Vec<String>,
    pub test_all_ips: bool,
    pub first_ip_only: bool,
    pub max_concurrent_ciphers: usize,
}

impl Default for ScanRequestNetwork {
    fn default() -> Self {
        Self {
            ipv4_only: false,
            ipv6_only: false,
            proxy: None,
            resolvers: Vec::new(),
            test_all_ips: false,
            first_ip_only: false,
            max_concurrent_ciphers: 10,
        }
    }
}
