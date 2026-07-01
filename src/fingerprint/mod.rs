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

const MAX_SIGNATURE_DATABASE_BYTES: u64 = 16 * 1024 * 1024;

fn read_signature_database(path: &std::path::Path) -> crate::Result<String> {
    let size = std::fs::metadata(path)
        .map_err(|source| crate::TlsError::FileSystemError {
            path: path.display().to_string(),
            source,
        })?
        .len();
    if size > MAX_SIGNATURE_DATABASE_BYTES {
        return Err(crate::TlsError::InvalidInput {
            message: format!(
                "Signature database too large: {} bytes (max {})",
                size, MAX_SIGNATURE_DATABASE_BYTES
            ),
        });
    }
    std::fs::read_to_string(path).map_err(|source| crate::TlsError::FileSystemError {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_probes_includes_hostname_and_port() {
        let probes = get_probes("example.com", 443).expect("JARM probes should build");
        assert_eq!(probes.len(), 10);
        assert_eq!(probes[0].options.hostname, "example.com");
        assert_eq!(probes[0].options.port, 443);
    }

    #[test]
    fn test_custom_signature_database_rejects_oversized_file_before_read() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("ja3.json");
        let file = std::fs::File::create(&path).expect("database file should be created");
        file.set_len(MAX_SIGNATURE_DATABASE_BYTES + 1)
            .expect("database file should be resized");

        let err = match Ja3Database::from_file(&path) {
            Ok(_) => panic!("oversized signature database should fail before read"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("Signature database too large"));
    }
}
