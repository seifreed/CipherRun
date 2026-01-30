// OpenSSL s_client integration
// Complete wrapper around OpenSSL s_client for advanced testing

use crate::Result;
use crate::security::{
    validate_cipher, validate_hostname, validate_port, validate_starttls_protocol,
};
use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use std::time::Duration;

/// OpenSSL s_client options
#[derive(Debug, Clone)]
pub struct OpenSslClientOptions {
    pub host: String,
    pub port: u16,
    pub starttls: Option<String>,
    pub servername: Option<String>,
    pub cipher: Option<String>,
    pub tls_version: Option<String>,
    pub showcerts: bool,
    pub debug: bool,
    pub state: bool,
    pub timeout: Option<Duration>,
    pub verify_locations: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub pass: Option<String>,
    pub proxy: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub bugs: bool,
    pub reconnect: bool,
}

impl Default for OpenSslClientOptions {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 443,
            starttls: None,
            servername: None,
            cipher: None,
            tls_version: None,
            showcerts: false,
            debug: false,
            state: false,
            timeout: None,
            verify_locations: None,
            cert: None,
            key: None,
            pass: None,
            proxy: None,
            alpn: None,
            bugs: false,
            reconnect: false,
        }
    }
}

/// OpenSSL s_client result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenSslClientResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub connection_info: Option<ConnectionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub protocol: String,
    pub cipher: String,
    pub certificate_chain: Vec<String>,
    pub verify_result: String,
    pub session_details: String,
}

/// OpenSSL s_client wrapper
pub struct OpenSslClient {
    openssl_path: String,
}

impl Default for OpenSslClient {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenSslClient {
    pub fn new() -> Self {
        Self {
            openssl_path: "openssl".to_string(),
        }
    }

    pub fn with_path(path: String) -> Self {
        Self { openssl_path: path }
    }

    /// Run OpenSSL s_client with the given options
    pub fn run(&self, options: &OpenSslClientOptions) -> Result<OpenSslClientResult> {
        // SECURITY: Validate all inputs to prevent command injection (CWE-78)
        validate_hostname(&options.host)
            .map_err(|e| crate::error::TlsError::Other(format!("Invalid hostname: {}", e)))?;

        validate_port(options.port)
            .map_err(|e| crate::error::TlsError::Other(format!("Invalid port: {}", e)))?;

        let mut cmd = Command::new(&self.openssl_path);
        cmd.arg("s_client");

        // Add host and port
        cmd.arg("-connect");
        cmd.arg(format!("{}:{}", options.host, options.port));

        // Add STARTTLS protocol
        if let Some(ref protocol) = options.starttls {
            // SECURITY: Validate STARTTLS protocol to prevent command injection
            validate_starttls_protocol(protocol).map_err(|e| {
                crate::error::TlsError::Other(format!("Invalid STARTTLS protocol: {}", e))
            })?;
            cmd.arg("-starttls");
            cmd.arg(protocol);
        }

        // Add SNI servername
        if let Some(ref servername) = options.servername {
            // SECURITY: Validate servername to prevent command injection
            validate_hostname(servername)
                .map_err(|e| crate::error::TlsError::Other(format!("Invalid servername: {}", e)))?;
            cmd.arg("-servername");
            cmd.arg(servername);
        }

        // Add cipher
        if let Some(ref cipher) = options.cipher {
            // SECURITY: Validate cipher string to prevent command injection
            validate_cipher(cipher)
                .map_err(|e| crate::error::TlsError::Other(format!("Invalid cipher: {}", e)))?;
            cmd.arg("-cipher");
            cmd.arg(cipher);
        }

        // Add TLS version
        if let Some(ref version) = options.tls_version {
            cmd.arg(version); // e.g., "-tls1_2", "-tls1_3"
        }

        // Add showcerts
        if options.showcerts {
            cmd.arg("-showcerts");
        }

        // Add debug
        if options.debug {
            cmd.arg("-debug");
        }

        // Add state
        if options.state {
            cmd.arg("-state");
        }

        // Add timeout
        if let Some(timeout) = options.timeout {
            cmd.arg("-timeout");
            cmd.arg(timeout.as_secs().to_string());
        }

        // Add verify locations
        if let Some(ref locations) = options.verify_locations {
            cmd.arg("-CAfile");
            cmd.arg(locations);
        }

        // Add client certificate
        if let Some(ref cert) = options.cert {
            cmd.arg("-cert");
            cmd.arg(cert);
        }

        // Add client key
        if let Some(ref key) = options.key {
            cmd.arg("-key");
            cmd.arg(key);
        }

        // Add passphrase
        if let Some(ref pass) = options.pass {
            cmd.arg("-pass");
            cmd.arg(format!("pass:{}", pass));
        }

        // Add proxy
        if let Some(ref proxy) = options.proxy {
            cmd.arg("-proxy");
            cmd.arg(proxy);
        }

        // Add ALPN
        if let Some(ref alpn) = options.alpn {
            cmd.arg("-alpn");
            cmd.arg(alpn.join(","));
        }

        // Add bugs workaround
        if options.bugs {
            cmd.arg("-bugs");
        }

        // Add reconnect
        if options.reconnect {
            cmd.arg("-reconnect");
        }

        // Execute
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd.output()?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);
        let success = output.status.success();

        let connection_info = if success {
            Some(parse_connection_info(&stdout))
        } else {
            None
        };

        Ok(OpenSslClientResult {
            success,
            stdout,
            stderr,
            exit_code,
            connection_info,
        })
    }

    /// Test cipher support using s_client
    pub fn test_cipher(&self, host: &str, port: u16, cipher: &str) -> Result<bool> {
        let options = OpenSslClientOptions {
            host: host.to_string(),
            port,
            cipher: Some(cipher.to_string()),
            servername: Some(host.to_string()),
            ..Default::default()
        };

        let result = self.run(&options)?;
        Ok(result.success)
    }

    /// Get full certificate chain
    pub fn get_certificate_chain(&self, host: &str, port: u16) -> Result<Vec<String>> {
        let options = OpenSslClientOptions {
            host: host.to_string(),
            port,
            servername: Some(host.to_string()),
            showcerts: true,
            ..Default::default()
        };

        let result = self.run(&options)?;

        if result.success {
            Ok(extract_certificates(&result.stdout))
        } else {
            Err(crate::error::TlsError::Other(
                "Failed to get certificate chain".to_string(),
            ))
        }
    }

    /// Test STARTTLS
    pub fn test_starttls(&self, host: &str, port: u16, protocol: &str) -> Result<bool> {
        let options = OpenSslClientOptions {
            host: host.to_string(),
            port,
            starttls: Some(protocol.to_string()),
            servername: Some(host.to_string()),
            ..Default::default()
        };

        let result = self.run(&options)?;
        Ok(result.success)
    }

    /// Test client certificate authentication
    pub fn test_client_cert(&self, host: &str, port: u16, cert: &str, key: &str) -> Result<bool> {
        let options = OpenSslClientOptions {
            host: host.to_string(),
            port,
            servername: Some(host.to_string()),
            cert: Some(cert.to_string()),
            key: Some(key.to_string()),
            ..Default::default()
        };

        let result = self.run(&options)?;
        Ok(result.success)
    }

    /// Get OpenSSL version
    pub fn get_version(&self) -> Result<String> {
        let output = Command::new(&self.openssl_path).arg("version").output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(crate::error::TlsError::Other(
                "Failed to get OpenSSL version".to_string(),
            ))
        }
    }
}

fn parse_connection_info(stdout: &str) -> ConnectionInfo {
    let mut protocol = String::new();
    let mut cipher = String::new();
    let mut verify_result = String::new();
    let mut session_details = String::new();

    for line in stdout.lines() {
        if line.contains("Protocol") && line.contains(":") {
            protocol = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.contains("Cipher") && line.contains(":") {
            cipher = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.contains("Verify return code:") {
            verify_result = line.trim().to_string();
        } else if line.starts_with("SSL-Session:") {
            session_details = line.trim().to_string();
        }
    }

    ConnectionInfo {
        protocol,
        cipher,
        certificate_chain: extract_certificates(stdout),
        verify_result,
        session_details,
    }
}

fn extract_certificates(stdout: &str) -> Vec<String> {
    let mut certificates = Vec::new();
    let mut current_cert = String::new();
    let mut in_cert = false;

    for line in stdout.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_cert.clear();
            current_cert.push_str(line);
            current_cert.push('\n');
        } else if line.contains("-----END CERTIFICATE-----") {
            current_cert.push_str(line);
            current_cert.push('\n');
            certificates.push(current_cert.clone());
            in_cert = false;
        } else if in_cert {
            current_cert.push_str(line);
            current_cert.push('\n');
        }
    }

    certificates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_certificates() {
        let stdout = r#"
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKJ
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKJ
-----END CERTIFICATE-----
"#;

        let certs = extract_certificates(stdout);
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn test_default_options() {
        let options = OpenSslClientOptions::default();
        assert_eq!(options.port, 443);
        assert!(!options.showcerts);
        assert!(!options.debug);
    }
}
