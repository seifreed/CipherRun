// Utils module - Utility functions

pub mod adaptive;
pub mod anycast;
pub mod dns_cache;
pub mod hints;
pub mod http;
pub mod ids_friendly;
pub mod insecure_tls;
pub mod mtls;
pub mod mx;
pub mod network;
pub mod network_runtime;
pub mod nmap;
pub mod path_ext;
pub mod proxy;
pub mod retry;
pub mod reverse_ptr;
pub mod sneaky;
pub mod sni_generator;
pub mod timing;

// MEDIUM PRIORITY Features (11-15)
pub mod custom_resolvers;
pub mod rate_limiter;

// Re-export commonly used traits
pub use path_ext::PathExt;

// Re-export SSL connection helpers for vulnerability testing
pub use network::{
    VulnSslConfig, VulnSslResult, test_cipher_support, test_vuln_ssl_connection,
    test_vuln_ssl_connection_outcome, try_vuln_ssl_connection,
};

#[cfg(test)]
mod tests {
    use super::PathExt;
    use std::path::Path;

    #[test]
    fn test_path_ext_reexport() {
        let path = Path::new("/tmp/example");
        assert_eq!(path.to_str_checked().unwrap(), "/tmp/example");
    }

    #[test]
    fn test_path_ext_reexport_relative() {
        let path = Path::new("relative/example");
        assert_eq!(path.to_str_checked().unwrap(), "relative/example");
    }

    #[test]
    fn test_path_ext_reexport_with_spaces() {
        let path = Path::new("relative/with space.txt");
        assert_eq!(path.to_str_checked().unwrap(), "relative/with space.txt");
    }
}
