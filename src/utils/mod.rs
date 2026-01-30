// Utils module - Utility functions

pub mod anycast;
pub mod crypto;
pub mod display;
pub mod dns_cache;
pub mod formatting;
pub mod hints;
pub mod ids_friendly;
pub mod mtls;
pub mod mx;
pub mod network;
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
    try_vuln_ssl_connection,
};
