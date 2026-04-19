mod connection;
mod ct_logs;
mod fingerprint;
mod http;
mod network;
mod phases;
mod queries;
mod scan;
mod scan_certs;
mod scan_ciphers;
mod scan_prefs;
mod scan_proto;
mod scan_scope;
mod scan_vulns;
mod starttls;
mod tls;
mod validation;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub use connection::ScanRequestConnection;
pub use ct_logs::ScanRequestCtLogs;
pub use fingerprint::ScanRequestFingerprint;
pub use http::ScanRequestHttp;
pub use network::ScanRequestNetwork;
pub use scan::ScanRequestScan;
pub use scan_certs::ScanRequestCerts;
pub use scan_ciphers::ScanRequestCiphers;
pub use scan_prefs::ScanRequestPrefs;
pub use scan_proto::ScanRequestProto;
pub use scan_scope::ScanRequestScope;
pub use scan_vulns::ScanRequestVulns;
pub use starttls::ScanRequestStarttls;
pub use tls::ScanRequestTls;

use super::OutputPresentationMode;

#[derive(Debug, Clone, Default)]
pub struct ScanRequest {
    pub target: Option<String>,
    pub port: Option<u16>,
    pub ip: Option<String>,
    pub scan: ScanRequestScan,
    pub network: ScanRequestNetwork,
    pub connection: ScanRequestConnection,
    pub tls: ScanRequestTls,
    pub fingerprint: ScanRequestFingerprint,
    pub http: ScanRequestHttp,
    pub starttls: ScanRequestStarttls,
    pub ct_logs: ScanRequestCtLogs,
    pub presentation_mode: OutputPresentationMode,
}
