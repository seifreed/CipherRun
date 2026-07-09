// OpenSSL s_client integration
// Complete wrapper around OpenSSL s_client for advanced testing

use crate::Result;
use crate::security::is_private_ip;
use crate::security::{
    validate_cipher, validate_hostname, validate_port, validate_starttls_protocol,
};
use crate::utils::network::canonical_target;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::process::{Command, Stdio};
use std::time::Duration;

/// OpenSSL s_client options
#[derive(Debug, Clone)]
pub struct OpenSslClientOptions {
    pub host: String,
    pub port: u16,
    pub starttls: Option<String>,
    pub xmpphost: Option<String>,
    pub servername: Option<String>,
    pub cipher: Option<String>,
    pub tls_version: Option<String>,
    pub showcerts: bool,
    pub debug: bool,
    pub state: bool,
    pub timeout: Option<Duration>,
    pub verify_locations: Option<OsString>,
    pub cert: Option<OsString>,
    pub key: Option<OsString>,
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
            xmpphost: None,
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
    openssl_path: OsString,
}

impl Default for OpenSslClient {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenSslClient {
    pub fn new() -> Self {
        Self {
            openssl_path: OsString::from("openssl"),
        }
    }

    pub fn with_path(path: impl Into<OsString>) -> Self {
        Self {
            openssl_path: path.into(),
        }
    }

    #[cfg(test)]
    fn openssl_path(&self) -> &std::ffi::OsStr {
        &self.openssl_path
    }

    /// Run OpenSSL s_client with the given options
    pub fn run(&self, options: &OpenSslClientOptions) -> Result<OpenSslClientResult> {
        // SECURITY: Validate all inputs to prevent command injection (CWE-78)
        validate_hostname(&options.host)
            .map_err(|e| crate::error::TlsError::Other(format!("Invalid hostname: {}", e)))?;
        reject_private_or_local_host(&options.host, "hostname", true)?;

        validate_port(options.port)
            .map_err(|e| crate::error::TlsError::Other(format!("Invalid port: {}", e)))?;

        let mut cmd = Command::new(&self.openssl_path);
        cmd.arg("s_client");

        // Add host and port
        cmd.arg("-connect");
        cmd.arg(connect_authority(&options.host, options.port));

        // Add STARTTLS protocol
        if let Some(ref protocol) = options.starttls {
            // SECURITY: Validate STARTTLS protocol to prevent command injection
            validate_starttls_protocol(protocol).map_err(|e| {
                crate::error::TlsError::Other(format!("Invalid STARTTLS protocol: {}", e))
            })?;
            cmd.arg("-starttls");
            let normalized_protocol = match protocol.trim().to_ascii_lowercase().as_str() {
                "postgresql" => "postgres".to_string(),
                other => other.to_string(),
            };
            cmd.arg(normalized_protocol);
        }

        if let Some(ref xmpphost) = options.xmpphost {
            validate_hostname(xmpphost)
                .map_err(|e| crate::error::TlsError::Other(format!("Invalid xmpphost: {}", e)))?;
            reject_private_or_local_host(xmpphost, "xmpphost", false)?;
            cmd.arg("-xmpphost");
            cmd.arg(xmpphost);
        }

        // Add SNI servername
        if let Some(ref servername) = options.servername {
            // SECURITY: Validate servername to prevent command injection
            validate_hostname(servername)
                .map_err(|e| crate::error::TlsError::Other(format!("Invalid servername: {}", e)))?;
            reject_private_or_local_host(servername, "servername", false)?;
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

        // Add TLS version (whitelisted to prevent argument injection)
        if let Some(ref version) = options.tls_version {
            const VALID_TLS_VERSIONS: &[&str] = &[
                "-ssl3",
                "-tls1",
                "-tls1_1",
                "-tls1_2",
                "-tls1_3",
                "-no_ssl3",
                "-no_tls1",
                "-no_tls1_1",
                "-no_tls1_2",
                "-no_tls1_3",
            ];
            if VALID_TLS_VERSIONS.contains(&version.as_str()) {
                cmd.arg(version);
            } else {
                return Err(crate::error::TlsError::Other(format!(
                    "Invalid TLS version flag: {}",
                    version
                )));
            }
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
            validate_file_path_arg(locations, "-CAfile/-CApath")?;
            cmd.arg(if std::path::Path::new(locations).is_dir() {
                "-CApath"
            } else {
                "-CAfile"
            });
            cmd.arg(locations);
        }

        // Add client certificate
        if let Some(ref cert) = options.cert {
            validate_file_path_arg(cert, "-cert")?;
            cmd.arg("-cert");
            cmd.arg(cert);
        }

        // Add client key
        if let Some(ref key) = options.key {
            validate_file_path_arg(key, "-key")?;
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
            let proxy = crate::utils::proxy::ProxyConfig::parse(proxy).map_err(|e| {
                crate::error::TlsError::Other(format!("Invalid proxy configuration: {e}"))
            })?;
            cmd.arg("-proxy");
            cmd.arg(proxy.authority());
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

        // OpenSSL may exit non-zero even after a completed handshake (e.g. server closes
        // the connection first). Parse connection info whenever stdout has content.
        let connection_info = if !stdout.is_empty() {
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

    /// List local OpenSSL ciphers available on this host.
    pub fn list_local_ciphers(&self) -> Result<Vec<String>> {
        let output = Command::new(&self.openssl_path)
            .args(["ciphers", "-v", "ALL"])
            .output()?;

        if !output.status.success() {
            return Err(crate::error::TlsError::Other(
                "Failed to list local OpenSSL ciphers".to_string(),
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
            .collect())
    }
}

fn validate_file_path_arg(value: &std::ffi::OsStr, flag: &str) -> crate::Result<()> {
    if value.to_string_lossy().starts_with('-') {
        crate::tls_bail!(
            "Invalid value for {}: '{}' looks like a flag, not a file path",
            flag,
            value.to_string_lossy()
        );
    }
    Ok(())
}

fn reject_private_or_local_host(
    host: &str,
    label: &str,
    allow_ip_literals: bool,
) -> crate::Result<()> {
    let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized_host == "localhost"
        || normalized_host.ends_with(".local")
        || normalized_host.ends_with(".internal")
    {
        crate::tls_bail!("Invalid {}: private/local hosts are not allowed", label);
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !allow_ip_literals {
            crate::tls_bail!("Invalid {}: IP literals are not allowed", label);
        }
        if is_private_ip(&ip) {
            crate::tls_bail!("Invalid {}: private/internal IP literals are not allowed", label);
        }
    }

    Ok(())
}

fn parse_connection_info(stdout: &str) -> ConnectionInfo {
    let mut protocol = String::new();
    let mut cipher = String::new();
    let mut verify_result = String::new();
    let mut session_details = String::new();
    let mut in_ssl_session = false;
    let mut cipher_from_session = false;

    for line in stdout.lines() {
        if line.starts_with("SSL-Session:") {
            in_ssl_session = true;
            session_details = line.trim().to_string();
        } else if line.contains("Cipher") && line.contains(":") {
            // Prefer the cipher reported inside the SSL-Session block, and within
            // it take the FIRST one: a later "Cipher  : (NONE)" line (emitted on a
            // closed/renegotiated session) must not clobber the negotiated value.
            // Outside the block, accept the first match as a fallback.
            let should_set = if in_ssl_session {
                !cipher_from_session
            } else {
                cipher.is_empty()
            };
            if should_set {
                let value = line
                    .split_once(':')
                    .map(|(_, value)| value.trim().to_string())
                    .unwrap_or_default();
                // "(NONE)" is emitted for a closed/un-negotiated session and is
                // not a real cipher, so never let it set or clobber the value.
                if !value.is_empty() && !value.eq_ignore_ascii_case("(none)") {
                    cipher = value;
                    cipher_from_session = in_ssl_session;
                }
            }
        } else if line.contains("Protocol") && line.contains(":") {
            protocol = line
                .split_once(':')
                .map(|(_, value)| value.trim().to_string())
                .unwrap_or_default();
        } else if line.contains("Verify return code:") {
            verify_result = line.trim().to_string();
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
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_cert.clear();
            current_cert.push_str(line);
            current_cert.push('\n');
        } else if line.starts_with("-----END CERTIFICATE-----") {
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

fn connect_authority(host: &str, port: u16) -> String {
    canonical_target(host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_with_path_preserves_non_utf8_path() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let path = OsString::from_vec(vec![b'o', b'p', b'e', b'n', b's', b's', b'l', 0xff]);
        let client = OpenSslClient::with_path(path.clone());

        assert_eq!(
            client.openssl_path().as_bytes(),
            path.as_os_str().as_bytes()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_file_path_arg_validation_accepts_non_utf8_path() {
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(vec![b'c', b'e', b'r', b't', 0xff]);

        validate_file_path_arg(&path, "-cert").expect("non-UTF8 path should stay valid");
        validate_file_path_arg(std::ffi::OsStr::new("-cert.pem"), "-cert")
            .expect_err("flag-like path should still be rejected");
    }

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
    fn test_extract_certificates_empty() {
        let certs = extract_certificates("no certs here");
        assert!(certs.is_empty());
    }

    #[test]
    fn test_default_options() {
        let options = OpenSslClientOptions::default();
        assert_eq!(options.port, 443);
        assert!(!options.showcerts);
        assert!(!options.debug);
    }

    #[test]
    fn test_parse_connection_info() {
        let stdout = r#"
Protocol  : TLSv1.2
Cipher    : ECDHE-RSA-AES256-GCM-SHA384
Verify return code: 0 (ok)
SSL-Session:
    Session-ID: 1234
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKJ
-----END CERTIFICATE-----
"#;

        let info = parse_connection_info(stdout);
        assert_eq!(info.protocol, "TLSv1.2");
        assert_eq!(info.cipher, "ECDHE-RSA-AES256-GCM-SHA384");
        assert!(info.verify_result.contains("Verify return code"));
        assert_eq!(info.session_details, "SSL-Session:");
        assert_eq!(info.certificate_chain.len(), 1);
    }

    #[test]
    fn test_parse_connection_info_ignores_trailing_none_cipher() {
        // A "(NONE)" Cipher line after the negotiated one (seen on a closed or
        // renegotiated session) must not clobber the real cipher.
        let stdout = r#"
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 1234
New, (NONE), Cipher is (NONE)
    Cipher    : (NONE)
"#;

        let info = parse_connection_info(stdout);
        assert_eq!(info.cipher, "ECDHE-RSA-AES256-GCM-SHA384");
    }

    #[test]
    fn test_parse_connection_info_preserves_colons_in_values() {
        let stdout = r#"
SSL-Session:
    Protocol  : TLSv1.3:draft
    Cipher    : TLS_AES_128_GCM_SHA256:extra
"#;

        let info = parse_connection_info(stdout);
        assert_eq!(info.protocol, "TLSv1.3:draft");
        assert_eq!(info.cipher, "TLS_AES_128_GCM_SHA256:extra");
    }

    #[test]
    fn test_run_rejects_invalid_inputs() {
        let client = OpenSslClient::new();

        let options = OpenSslClientOptions {
            host: "bad host\n".to_string(),
            ..Default::default()
        };
        let err = client.run(&options).expect_err("should fail");
        assert!(err.to_string().contains("Invalid hostname"));

        let options = OpenSslClientOptions {
            host: "example.com".to_string(),
            port: 0,
            ..Default::default()
        };
        let err = client.run(&options).expect_err("should fail");
        assert!(err.to_string().contains("Invalid port"));

        let options = OpenSslClientOptions {
            host: "example.com".to_string(),
            cipher: Some("AES128-SHA;rm".to_string()),
            ..Default::default()
        };
        let err = client.run(&options).expect_err("should fail");
        assert!(err.to_string().contains("Invalid cipher"));

        let options = OpenSslClientOptions {
            host: "example.com".to_string(),
            starttls: Some("invalid".to_string()),
            ..Default::default()
        };
        let err = client.run(&options).expect_err("should fail");
        assert!(err.to_string().contains("Invalid STARTTLS"));

        let options = OpenSslClientOptions {
            host: "example.com".to_string(),
            proxy: Some("http://proxy.example.com/path".to_string()),
            ..Default::default()
        };
        let err = client.run(&options).expect_err("should fail");
        assert!(err.to_string().contains("Invalid proxy"));
    }

    #[cfg(unix)]
    #[test]
    fn test_run_normalizes_postgresql_starttls_alias() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir should be created");
        let script = dir.path().join("openssl");
        fs::write(
            &script,
            "#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit 0\n",
        )
        .expect("script should be written");
        let mut perms = fs::metadata(&script).expect("script metadata should exist").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).expect("script should be executable");

        let client = OpenSslClient::with_path(&script);
        let options = OpenSslClientOptions {
            host: "example.com".to_string(),
            starttls: Some("SMTP".to_string()),
            ..Default::default()
        };
        let result = client.run(&options).expect("script should run");

        assert!(result.stdout.contains("-starttls\nsmtp"));
        assert!(result.success);

        let options = OpenSslClientOptions {
            host: "example.com".to_string(),
            starttls: Some("postgresql".to_string()),
            ..Default::default()
        };
        let result = client.run(&options).expect("script should run");

        assert!(result.stdout.contains("-starttls\npostgres"));
        assert!(result.success);
    }

    #[test]
    fn test_run_rejects_private_or_local_targets_and_sni() {
        let client = OpenSslClient::new();

        let options = OpenSslClientOptions {
            host: "localhost".to_string(),
            ..Default::default()
        };
        let err = client
            .run(&options)
            .expect_err("localhost host should fail");
        assert!(err.to_string().contains("private/local hosts"));

        let options = OpenSslClientOptions {
            host: "example.com".to_string(),
            servername: Some("127.0.0.1".to_string()),
            ..Default::default()
        };
        let err = client
            .run(&options)
            .expect_err("IP literal SNI should fail");
        assert!(err.to_string().contains("IP literals"));

        let options = OpenSslClientOptions {
            host: "example.com".to_string(),
            xmpphost: Some("localhost".to_string()),
            ..Default::default()
        };
        let err = client
            .run(&options)
            .expect_err("localhost xmpphost should fail");
        assert!(err.to_string().contains("private/local hosts"));
    }

    #[test]
    fn test_parse_connection_info_with_missing_fields() {
        let stdout = "Verify return code: 0 (ok)\n";
        let info = parse_connection_info(stdout);
        assert_eq!(info.protocol, "");
        assert_eq!(info.cipher, "");
        assert!(info.verify_result.contains("Verify return code"));
        assert_eq!(info.session_details, "");
        assert!(info.certificate_chain.is_empty());
    }

    #[test]
    fn test_connect_authority_brackets_ipv6() {
        assert_eq!(connect_authority("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(connect_authority("[2001:db8::1]", 443), "[2001:db8::1]:443");
    }
}
