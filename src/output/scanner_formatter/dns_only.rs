use super::ScannerFormatter;
use crate::output::dns_only::DnsOnlyMode;

impl<'a> ScannerFormatter<'a> {
    pub fn display_dns_only_results(&self, results: &crate::scanner::ScanResults) {
        let output = DnsOnlyMode::format_scan_results(results);
        if !output.is_empty() {
            println!("{}", output);
        }
    }
}
