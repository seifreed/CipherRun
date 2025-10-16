// External tool integrations
// OpenSSL s_client, aha, xxd, dig/host

pub mod aha;
pub mod dns_tools;
pub mod openssl_client;
pub mod xxd;

use crate::Result;
use std::process::Command;

/// Check if an external tool is available in PATH
pub fn check_tool_available(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Get version of an external tool
pub fn get_tool_version(tool: &str) -> Result<String> {
    let output = Command::new(tool).arg("--version").output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(anyhow::anyhow!("Failed to get version for {}", tool))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_tool_available() {
        // Most systems should have 'ls'
        assert!(check_tool_available("ls"));

        // This tool definitely doesn't exist
        assert!(!check_tool_available("nonexistent_tool_xyz123"));
    }
}
