#[test]
fn test_scan_options_full() {
    use cipherrun::api::models::request::ScanOptions;

    let options = ScanOptions::full();
    assert!(options.test_protocols);
    assert!(options.test_ciphers);
    assert!(options.test_vulnerabilities);
    assert!(options.analyze_certificates);
    assert!(options.test_http_headers);
    assert!(options.client_simulation);
    assert!(options.full_scan);
}

#[test]
fn test_scan_options_quick() {
    use cipherrun::api::models::request::ScanOptions;

    let options = ScanOptions::quick();
    assert!(options.test_protocols);
    assert!(!options.test_ciphers);
    assert!(!options.test_vulnerabilities);
    assert!(options.analyze_certificates);
    assert!(!options.test_http_headers);
    assert!(!options.client_simulation);
    assert!(!options.full_scan);
}

#[test]
fn test_scan_options_default() {
    use cipherrun::api::models::request::ScanOptions;

    let options = ScanOptions::default();
    assert!(!options.test_protocols);
    assert!(!options.test_ciphers);
    assert!(!options.test_vulnerabilities);
    assert!(!options.analyze_certificates);
    assert!(!options.test_http_headers);
    assert!(!options.client_simulation);
    assert!(!options.full_scan);
}
