// Fingerprint module - TLS fingerprinting (client and server)

pub mod capture;
pub mod capture_server;
pub mod client_hello_capture;
pub mod ja3;
pub mod ja3s;
pub mod jarm;
pub mod jarm_probes;
pub mod server_hello;

pub use capture::ClientHelloNetworkCapture;
pub use capture_server::ServerHelloNetworkCapture;
pub use client_hello_capture::{ClientHelloCapture, Extension as ClientExtension};
pub use ja3::{Ja3Database, Ja3Fingerprint, Ja3Signature};
pub use ja3s::{
    CdnDetection, Ja3sDatabase, Ja3sFingerprint, Ja3sSignature, LoadBalancerInfo, ServerType,
};
pub use jarm::{JarmDatabase, JarmFingerprint, JarmFingerprinter, JarmSignature};
pub use jarm_probes::{JarmProbe, JarmProbeOptions, get_probes};
pub use server_hello::{Extension as ServerExtension, ServerHelloCapture};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_probes_includes_hostname_and_port() {
        let probes = get_probes("example.com", 443);
        assert_eq!(probes.len(), 10);
        assert_eq!(probes[0].options.hostname, "example.com");
        assert_eq!(probes[0].options.port, 443);
    }
}
