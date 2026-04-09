// Shared STARTTLS negotiation template for text-based protocols.
//
// Protocols like IMAP, POP3, SMTP, LMTP, FTP, NNTP, and Sieve all follow
// the same 5-step negotiation pattern with protocol-specific configuration.
// This module provides a data-driven template that eliminates code duplication.

use super::protocols::StarttlsProtocol;
use super::response;
use crate::Result;
use crate::error::TlsError;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Configuration for a text-based STARTTLS negotiation.
pub struct TextProtocolConfig {
    pub protocol_name: &'static str,
    pub protocol: StarttlsProtocol,
    pub greeting: GreetingStyle,
    pub capability: Option<CapabilityConfig>,
    pub starttls_command: &'static [u8],
    pub success: SuccessCheck,
}

/// How to detect the server greeting.
pub enum GreetingStyle {
    /// Match by string prefix (e.g., IMAP: "* OK", POP3: "+OK").
    Prefix(&'static str),
    /// Match by 3-digit status code using `read_status_line` (e.g., SMTP: 220).
    StatusCode(u16),
    /// Match any of several status codes (e.g., NNTP: 200 or 201).
    StatusCodes(&'static [u16]),
    /// Read greeting as multi-line status response (e.g., FTP: 220).
    MultilineStatus(u16),
    /// No greeting — server sends capabilities immediately (e.g., Sieve).
    None,
}

/// Configuration for the capability-check step.
pub struct CapabilityConfig {
    pub command: CapabilityCommand,
    pub starttls_marker: &'static str,
    pub response_style: CapabilityResponseStyle,
}

/// How to send the capability query command.
pub enum CapabilityCommand {
    /// Fixed command bytes (e.g., IMAP: b"a001 CAPABILITY\r\n").
    Static(&'static [u8]),
    /// Command that requires hostname interpolation (e.g., SMTP: "EHLO {}\r\n").
    WithHostname(&'static str),
    /// No command — server sends capabilities on connect (e.g., Sieve).
    None,
}

/// How to parse the capability response.
pub enum CapabilityResponseStyle {
    /// Tagged response (IMAP): read lines until `ok_prefix`, error on `error_prefixes`.
    UntilTagged {
        ok_prefix: &'static str,
        error_prefixes: &'static [&'static str],
    },
    /// Dot-terminated (POP3, NNTP): optionally validate a first-line prefix or status.
    DotTerminated {
        first_line_prefix: Option<&'static str>,
        first_line_status: Option<u16>,
    },
    /// Multi-line status code (SMTP/LMTP: 250-/250).
    MultiLineStatus { code: u16 },
    /// Read lines until a prefix match (Sieve: until "OK").
    UntilPrefix(&'static str),
}

/// How to validate the STARTTLS response.
pub enum SuccessCheck {
    /// Success if response line starts with prefix (e.g., IMAP: "a002 OK").
    Prefix(&'static str),
    /// Success if status code matches (e.g., SMTP: 220, FTP: 234).
    StatusCode(u16),
}

/// Execute the STARTTLS negotiation using the given protocol configuration.
///
/// The `hostname` parameter is only used when `CapabilityCommand::WithHostname`
/// is configured (SMTP/LMTP EHLO/LHLO). Pass `""` for stateless negotiators.
pub async fn negotiate(
    config: &TextProtocolConfig,
    hostname: &str,
    stream: &mut TcpStream,
) -> Result<()> {
    let mut reader = BufReader::new(stream);

    // Step 1: Read server greeting
    read_greeting(config, &mut reader).await?;

    // Step 2-3: Send capability command and check for STARTTLS support
    check_capability(config, hostname, &mut reader).await?;

    // Step 4: Send STARTTLS command
    reader.get_mut().write_all(config.starttls_command).await?;
    reader.get_mut().flush().await?;

    // Step 5: Validate STARTTLS response
    validate_success(config, &mut reader).await?;

    Ok(())
}

async fn read_greeting(
    config: &TextProtocolConfig,
    reader: &mut BufReader<&mut TcpStream>,
) -> Result<()> {
    match &config.greeting {
        GreetingStyle::Prefix(prefix) => {
            let line = response::read_line(reader).await?;
            if !line.starts_with(prefix) {
                return Err(TlsError::StarttlsError {
                    protocol: config.protocol_name.to_string(),
                    details: format!("Greeting failed: {}", line),
                });
            }
        }
        GreetingStyle::StatusCode(expected) => {
            let (code, _) = response::read_status_line(reader, config.protocol_name).await?;
            if code != *expected {
                return Err(TlsError::UnexpectedResponse {
                    details: format!(
                        "{} greeting failed: expected {}, got {}",
                        config.protocol_name, expected, code
                    ),
                });
            }
        }
        GreetingStyle::StatusCodes(expected) => {
            let (code, _) = response::read_status_line(reader, config.protocol_name).await?;
            if !expected.contains(&code) {
                return Err(TlsError::UnexpectedResponse {
                    details: format!(
                        "{} greeting failed: expected one of {:?}, got {}",
                        config.protocol_name, expected, code
                    ),
                });
            }
        }
        GreetingStyle::MultilineStatus(expected) => {
            let (code, _) =
                response::read_multiline_status(reader, config.protocol_name, 100).await?;
            if code != *expected {
                return Err(TlsError::UnexpectedResponse {
                    details: format!(
                        "{} greeting failed: expected {}, got {}",
                        config.protocol_name, expected, code
                    ),
                });
            }
        }
        GreetingStyle::None => {}
    }
    Ok(())
}

async fn check_capability(
    config: &TextProtocolConfig,
    hostname: &str,
    reader: &mut BufReader<&mut TcpStream>,
) -> Result<()> {
    let cap_config = match &config.capability {
        Some(c) => c,
        // Sieve: no command, caps come on connect — check via UntilPrefix in greeting
        // FTP: no capability check, go straight to STARTTLS
        None => return Ok(()),
    };

    // Send capability command (if any — Sieve sends caps on connect)
    match &cap_config.command {
        CapabilityCommand::Static(cmd) => {
            reader.get_mut().write_all(cmd).await?;
            reader.get_mut().flush().await?;
        }
        CapabilityCommand::WithHostname(template) => {
            let cmd = template.replace("{}", hostname);
            reader.get_mut().write_all(cmd.as_bytes()).await?;
            reader.get_mut().flush().await?;
        }
        CapabilityCommand::None => {}
    }

    // Read capability response and check for STARTTLS marker
    let supported = match &cap_config.response_style {
        CapabilityResponseStyle::UntilTagged {
            ok_prefix,
            error_prefixes,
        } => {
            read_tagged_capabilities(reader, config, cap_config, ok_prefix, error_prefixes).await?
        }
        CapabilityResponseStyle::DotTerminated {
            first_line_prefix,
            first_line_status,
        } => {
            read_dot_terminated_capabilities(
                reader,
                config,
                cap_config,
                *first_line_prefix,
                *first_line_status,
            )
            .await?
        }
        CapabilityResponseStyle::MultiLineStatus { code } => {
            read_multiline_capabilities(reader, config, cap_config, *code).await?
        }
        CapabilityResponseStyle::UntilPrefix(prefix) => {
            read_until_prefix_capabilities(reader, cap_config, prefix).await?
        }
    };

    if !supported {
        return Err(TlsError::StarttlsError {
            protocol: config.protocol_name.to_string(),
            details: "Server does not support STARTTLS".to_string(),
        });
    }

    Ok(())
}

async fn read_tagged_capabilities(
    reader: &mut BufReader<&mut TcpStream>,
    config: &TextProtocolConfig,
    cap: &CapabilityConfig,
    ok_prefix: &str,
    error_prefixes: &[&str],
) -> Result<bool> {
    let mut supported = false;
    loop {
        let line = response::read_line(reader).await?;
        if line.to_uppercase().contains(cap.starttls_marker) {
            supported = true;
        }
        if line.starts_with(ok_prefix) {
            break;
        }
        if error_prefixes.iter().any(|p| line.starts_with(p)) {
            return Err(TlsError::StarttlsError {
                protocol: config.protocol_name.to_string(),
                details: "Capability command failed".to_string(),
            });
        }
    }
    Ok(supported)
}

async fn read_dot_terminated_capabilities(
    reader: &mut BufReader<&mut TcpStream>,
    config: &TextProtocolConfig,
    cap: &CapabilityConfig,
    first_line_prefix: Option<&str>,
    first_line_status: Option<u16>,
) -> Result<bool> {
    // Validate first line if required
    if let Some(prefix) = first_line_prefix {
        let line = response::read_line(reader).await?;
        if !line.starts_with(prefix) {
            return Err(TlsError::StarttlsError {
                protocol: config.protocol_name.to_string(),
                details: "Capability command failed".to_string(),
            });
        }
    } else if let Some(expected_code) = first_line_status {
        let (code, _) = response::read_status_line(reader, config.protocol_name).await?;
        if code != expected_code {
            return Err(TlsError::UnexpectedResponse {
                details: format!("Capability response failed: expected {}", expected_code),
            });
        }
    }

    let mut supported = false;
    loop {
        let line = response::read_line(reader).await?;
        let trimmed = line.trim();
        if trimmed == "." {
            break;
        }
        if trimmed.to_uppercase().contains(cap.starttls_marker) {
            supported = true;
        }
    }
    Ok(supported)
}

async fn read_multiline_capabilities(
    reader: &mut BufReader<&mut TcpStream>,
    config: &TextProtocolConfig,
    cap: &CapabilityConfig,
    expected_code: u16,
) -> Result<bool> {
    let mut supported = false;
    loop {
        let (code, line) = response::read_status_line(reader, config.protocol_name).await?;
        if code != expected_code {
            return Err(TlsError::UnexpectedResponse {
                details: format!(
                    "{} capability failed: expected {}, got {}",
                    config.protocol_name, expected_code, code
                ),
            });
        }
        if line.to_uppercase().contains(cap.starttls_marker) {
            supported = true;
        }
        // Last line: "NNN " (space after code, not dash "NNN-")
        if line.len() >= 4 && &line[3..4] == " " {
            break;
        }
    }
    Ok(supported)
}

async fn read_until_prefix_capabilities(
    reader: &mut BufReader<&mut TcpStream>,
    cap: &CapabilityConfig,
    prefix: &str,
) -> Result<bool> {
    let mut supported = false;
    loop {
        let line = response::read_line(reader).await?;
        if line.starts_with(prefix) {
            break;
        }
        if line.to_uppercase().contains(cap.starttls_marker) {
            supported = true;
        }
    }
    Ok(supported)
}

async fn validate_success(
    config: &TextProtocolConfig,
    reader: &mut BufReader<&mut TcpStream>,
) -> Result<()> {
    match &config.success {
        SuccessCheck::Prefix(prefix) => {
            let line = response::read_line(reader).await?;
            if !line.starts_with(prefix) {
                return Err(TlsError::StarttlsError {
                    protocol: config.protocol_name.to_string(),
                    details: format!("STARTTLS failed: {}", line),
                });
            }
        }
        SuccessCheck::StatusCode(expected) => {
            let (code, response) = response::read_status_line(reader, config.protocol_name).await?;
            if code != *expected {
                return Err(TlsError::StarttlsError {
                    protocol: config.protocol_name.to_string(),
                    details: format!("Expected {}, got {}: {}", expected, code, response),
                });
            }
        }
    }
    Ok(())
}
