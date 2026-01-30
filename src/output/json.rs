// JSON Output Module

use crate::Result;
use crate::scanner::ScanResults;
use crate::scanner::multi_ip::MultiIpScanReport;

/// Generate JSON output from scan results
pub fn generate_json(results: &ScanResults, pretty: bool) -> Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(results)?)
    } else {
        Ok(serde_json::to_string(results)?)
    }
}

/// Generate JSON output from multi-IP scan report
pub fn generate_multi_ip_json(report: &MultiIpScanReport, pretty: bool) -> Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(report)?)
    } else {
        Ok(serde_json::to_string(report)?)
    }
}

/// Write JSON to file
pub fn write_json_file(results: &ScanResults, path: &str, pretty: bool) -> Result<()> {
    let json = generate_json(results, pretty)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Write multi-IP report JSON to file
pub fn write_multi_ip_json_file(
    report: &MultiIpScanReport,
    path: &str,
    pretty: bool,
) -> Result<()> {
    let json = generate_multi_ip_json(report, pretty)?;
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_generation() {
        let results = ScanResults {
            target: "example.com:443".to_string(),
            scan_time_ms: 1000,
            ..Default::default()
        };

        let json = generate_json(&results, false).expect("test assertion should succeed");
        assert!(json.contains("example.com"));

        let pretty_json = generate_json(&results, true).expect("test assertion should succeed");
        assert!(pretty_json.contains("example.com"));
        assert!(pretty_json.contains("\n")); // Check for pretty printing
    }
}
