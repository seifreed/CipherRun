use crate::ciphers::CipherSuite;
use crate::scanner::ScanResults;
use crate::scanner::inconsistency::SingleIpScanResult;
use std::net::IpAddr;

pub(crate) fn make_cipher(
    openssl_name: &str,
    bits: u16,
    key_exchange: &str,
    encryption: &str,
) -> CipherSuite {
    CipherSuite {
        hexcode: "0001".to_string(),
        openssl_name: openssl_name.to_string(),
        iana_name: openssl_name.to_string(),
        protocol: "TLSv1.2".to_string(),
        key_exchange: key_exchange.to_string(),
        authentication: "RSA".to_string(),
        encryption: encryption.to_string(),
        mac: "SHA256".to_string(),
        bits,
        export: false,
    }
}

pub(crate) fn successful_ip_scan(
    ip: IpAddr,
    scan_result: ScanResults,
    scan_duration_ms: u64,
) -> SingleIpScanResult {
    SingleIpScanResult {
        ip,
        scan_result,
        scan_duration_ms,
        error: None,
    }
}
