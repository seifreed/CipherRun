// CipherRun - A fast, modular, and scalable TLS/SSL security scanner
// Copyright (C) 2024 CipherRun Team
// Licensed under GPL-2.0

//! TLS/SSL Protocol Constants
//!
//! This module provides centralized constants for TLS/SSL protocol operations,
//! eliminating magic numbers throughout the codebase and ensuring consistency.
//! All constants are documented with RFC references where applicable.

use std::time::Duration;

// =============================================================================
// TLS Content Types (RFC 8446 Section 5.1, RFC 5246 Section 6.2.1)
// =============================================================================

/// TLS Content Type: Change Cipher Spec (0x14)
///
/// Used to signal a change in the encryption parameters.
/// Deprecated in TLS 1.3 but still used in TLS 1.2 and earlier.
///
/// Reference: RFC 5246 Section 7.1
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;

/// TLS Content Type: Alert (0x15)
///
/// Used to convey closure alerts and error messages.
///
/// Reference: RFC 8446 Section 6, RFC 5246 Section 7.2
pub const CONTENT_TYPE_ALERT: u8 = 0x15;

/// TLS Content Type: Handshake (0x16)
///
/// Used for handshake messages including ClientHello, ServerHello,
/// Certificate, CertificateVerify, Finished, etc.
///
/// Reference: RFC 8446 Section 4, RFC 5246 Section 7.4
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS Content Type: Application Data (0x17)
///
/// Used to carry encrypted application data after the handshake is complete.
///
/// Reference: RFC 8446 Section 5.2, RFC 5246 Section 10
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

/// TLS Content Type: Heartbeat (0x18)
///
/// Used for the Heartbeat Extension (keep-alive functionality).
/// Note: This is the content type exploited by the Heartbleed vulnerability.
///
/// Reference: RFC 6520
pub const CONTENT_TYPE_HEARTBEAT: u8 = 0x18;

// =============================================================================
// TLS Handshake Types (RFC 8446 Section 4, RFC 5246 Section 7.4)
// =============================================================================

/// Handshake Type: HelloRequest (0x00)
///
/// Sent by server to initiate a new handshake (TLS 1.2 and earlier).
/// Not used in TLS 1.3.
///
/// Reference: RFC 5246 Section 7.4.1.1
pub const HANDSHAKE_TYPE_HELLO_REQUEST: u8 = 0x00;

/// Handshake Type: ClientHello (0x01)
///
/// Initial message sent by the client to initiate a TLS handshake.
/// Contains protocol version, random data, cipher suites, and extensions.
///
/// Reference: RFC 8446 Section 4.1.2, RFC 5246 Section 7.4.1.2
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// Handshake Type: ServerHello (0x02)
///
/// Server's response to ClientHello, selecting protocol version,
/// cipher suite, and other parameters.
///
/// Reference: RFC 8446 Section 4.1.3, RFC 5246 Section 7.4.1.3
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// Handshake Type: HelloVerifyRequest (0x03)
///
/// Used in DTLS to verify client's address before allocating state.
///
/// Reference: RFC 6347 Section 4.2.1
pub const HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST: u8 = 0x03;

/// Handshake Type: NewSessionTicket (0x04)
///
/// Used for session resumption without server-side state.
///
/// Reference: RFC 8446 Section 4.6.1, RFC 5077
pub const HANDSHAKE_TYPE_NEW_SESSION_TICKET: u8 = 0x04;

/// Handshake Type: EndOfEarlyData (0x05)
///
/// Marks the end of 0-RTT data in TLS 1.3.
///
/// Reference: RFC 8446 Section 4.5
pub const HANDSHAKE_TYPE_END_OF_EARLY_DATA: u8 = 0x05;

/// Handshake Type: EncryptedExtensions (0x08)
///
/// TLS 1.3 message containing encrypted extension data.
///
/// Reference: RFC 8446 Section 4.3.1
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 0x08;

/// Handshake Type: Certificate (0x0B)
///
/// Contains the certificate chain for authentication.
///
/// Reference: RFC 8446 Section 4.4.2, RFC 5246 Section 7.4.2
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 0x0B;

/// Handshake Type: ServerKeyExchange (0x0C)
///
/// Contains server's key exchange parameters (TLS 1.2 and earlier).
/// Not used in TLS 1.3.
///
/// Reference: RFC 5246 Section 7.4.3
pub const HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE: u8 = 0x0C;

/// Handshake Type: CertificateRequest (0x0D)
///
/// Server requests a certificate from the client (mutual TLS).
///
/// Reference: RFC 8446 Section 4.3.2, RFC 5246 Section 7.4.4
pub const HANDSHAKE_TYPE_CERTIFICATE_REQUEST: u8 = 0x0D;

/// Handshake Type: ServerHelloDone (0x0E)
///
/// Indicates server has finished its part of the handshake (TLS 1.2 and earlier).
/// Not used in TLS 1.3.
///
/// Reference: RFC 5246 Section 7.4.5
pub const HANDSHAKE_TYPE_SERVER_HELLO_DONE: u8 = 0x0E;

/// Handshake Type: CertificateVerify (0x0F)
///
/// Proves possession of the private key corresponding to the certificate.
///
/// Reference: RFC 8446 Section 4.4.3, RFC 5246 Section 7.4.8
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 0x0F;

/// Handshake Type: ClientKeyExchange (0x10)
///
/// Contains client's key exchange parameters (TLS 1.2 and earlier).
/// Not used in TLS 1.3.
///
/// Reference: RFC 5246 Section 7.4.7
pub const HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE: u8 = 0x10;

/// Handshake Type: Finished (0x14)
///
/// Final handshake message, contains verification data to ensure
/// handshake integrity.
///
/// Reference: RFC 8446 Section 4.4.4, RFC 5246 Section 7.4.9
pub const HANDSHAKE_TYPE_FINISHED: u8 = 0x14;

/// Handshake Type: CertificateURL (0x15)
///
/// Alternative to Certificate message, provides URLs instead of full certificates.
///
/// Reference: RFC 6066 Section 11
pub const HANDSHAKE_TYPE_CERTIFICATE_URL: u8 = 0x15;

/// Handshake Type: CertificateStatus (0x16)
///
/// Contains OCSP response for certificate validation.
///
/// Reference: RFC 6066 Section 8
pub const HANDSHAKE_TYPE_CERTIFICATE_STATUS: u8 = 0x16;

/// Handshake Type: KeyUpdate (0x18)
///
/// Used to update traffic keys in TLS 1.3.
///
/// Reference: RFC 8446 Section 4.6.3
pub const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 0x18;

/// Handshake Type: MessageHash (0xFE)
///
/// Special synthetic handshake message type used in TLS 1.3.
///
/// Reference: RFC 8446 Section 4.4.1
pub const HANDSHAKE_TYPE_MESSAGE_HASH: u8 = 0xFE;

// =============================================================================
// TLS Alert Levels (RFC 8446 Section 6, RFC 5246 Section 7.2)
// =============================================================================

/// Alert Level: Warning (0x01)
///
/// Indicates a non-fatal error condition.
pub const ALERT_LEVEL_WARNING: u8 = 0x01;

/// Alert Level: Fatal (0x02)
///
/// Indicates a fatal error that terminates the connection.
pub const ALERT_LEVEL_FATAL: u8 = 0x02;

// =============================================================================
// TLS Alert Descriptions (RFC 8446 Section 6.2, RFC 5246 Section 7.2)
// =============================================================================

/// Alert: Close Notify (0)
pub const ALERT_CLOSE_NOTIFY: u8 = 0;

/// Alert: Unexpected Message (10)
pub const ALERT_UNEXPECTED_MESSAGE: u8 = 10;

/// Alert: Bad Record MAC (20)
pub const ALERT_BAD_RECORD_MAC: u8 = 20;

/// Alert: Handshake Failure (40)
pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;

/// Alert: Bad Certificate (42)
pub const ALERT_BAD_CERTIFICATE: u8 = 42;

/// Alert: Certificate Revoked (44)
pub const ALERT_CERTIFICATE_REVOKED: u8 = 44;

/// Alert: Certificate Expired (45)
pub const ALERT_CERTIFICATE_EXPIRED: u8 = 45;

/// Alert: Certificate Unknown (46)
pub const ALERT_CERTIFICATE_UNKNOWN: u8 = 46;

/// Alert: Illegal Parameter (47)
pub const ALERT_ILLEGAL_PARAMETER: u8 = 47;

/// Alert: Unknown CA (48)
pub const ALERT_UNKNOWN_CA: u8 = 48;

/// Alert: Decode Error (50)
pub const ALERT_DECODE_ERROR: u8 = 50;

/// Alert: Protocol Version (70)
pub const ALERT_PROTOCOL_VERSION: u8 = 70;

/// Alert: Insufficient Security (71)
pub const ALERT_INSUFFICIENT_SECURITY: u8 = 71;

/// Alert: Internal Error (80)
pub const ALERT_INTERNAL_ERROR: u8 = 80;

/// Alert: Unrecognized Name (112)
pub const ALERT_UNRECOGNIZED_NAME: u8 = 112;

// =============================================================================
// TLS Extension Types (IANA TLS ExtensionType Values)
// =============================================================================

/// Extension: Server Name Indication (0x0000)
///
/// Allows client to indicate the hostname it's attempting to connect to.
///
/// Reference: RFC 6066 Section 3
pub const EXTENSION_SERVER_NAME: u16 = 0x0000;

/// Extension: Supported Groups (0x000A)
///
/// Indicates supported elliptic curves or finite field groups.
/// Formerly called "elliptic_curves".
///
/// Reference: RFC 8422 Section 5.1, RFC 7919
pub const EXTENSION_SUPPORTED_GROUPS: u16 = 0x000A;

/// Extension: EC Point Formats (0x000B)
///
/// Indicates supported elliptic curve point formats.
///
/// Reference: RFC 8422 Section 5.1
pub const EXTENSION_EC_POINT_FORMATS: u16 = 0x000B;

/// Extension: Signature Algorithms (0x000D)
///
/// Indicates supported signature algorithms.
///
/// Reference: RFC 8446 Section 4.2.3, RFC 5246 Section 7.4.1.4.1
pub const EXTENSION_SIGNATURE_ALGORITHMS: u16 = 0x000D;

/// Extension: Application Layer Protocol Negotiation (0x0010)
///
/// Allows negotiation of application protocol (e.g., http/1.1, h2).
///
/// Reference: RFC 7301
pub const EXTENSION_ALPN: u16 = 0x0010;

/// Extension: Encrypt-then-MAC (0x0016)
///
/// Changes MAC calculation order to encrypt-then-MAC for better security.
///
/// Reference: RFC 7366
pub const EXTENSION_ENCRYPT_THEN_MAC: u16 = 0x0016;

/// Extension: Extended Master Secret (0x0017)
///
/// Binds master secret to handshake log for better security.
///
/// Reference: RFC 7627
pub const EXTENSION_EXTENDED_MASTER_SECRET: u16 = 0x0017;

/// Extension: Session Ticket (0x0023)
///
/// Enables stateless session resumption.
///
/// Reference: RFC 5077
pub const EXTENSION_SESSION_TICKET: u16 = 0x0023;

/// Extension: Supported Versions (0x002B)
///
/// TLS 1.3 extension to indicate supported TLS versions.
///
/// Reference: RFC 8446 Section 4.2.1
pub const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002B;

/// Extension: Key Share (0x0033)
///
/// TLS 1.3 extension containing key exchange information.
///
/// Reference: RFC 8446 Section 4.2.8
pub const EXTENSION_KEY_SHARE: u16 = 0x0033;

/// Extension: Renegotiation Info (0xFF01)
///
/// Prevents renegotiation attacks.
///
/// Reference: RFC 5746
pub const EXTENSION_RENEGOTIATION_INFO: u16 = 0xFF01;

// =============================================================================
// Default Network Ports
// =============================================================================

/// Default port for HTTPS (HTTP over TLS)
pub const PORT_HTTPS: u16 = 443;

/// Default port for SMTP (mail submission, plaintext)
pub const PORT_SMTP: u16 = 25;

/// Default port for SMTPS (SMTP over implicit TLS)
pub const PORT_SMTPS: u16 = 465;

/// Default port for SMTP Submission (mail submission with STARTTLS)
pub const PORT_SMTP_SUBMISSION: u16 = 587;

/// Default port for IMAPS (IMAP over implicit TLS)
pub const PORT_IMAPS: u16 = 993;

/// Default port for POP3S (POP3 over implicit TLS)
pub const PORT_POP3S: u16 = 995;

/// Default port for FTPS (FTP over implicit TLS)
pub const PORT_FTPS: u16 = 990;

/// Default port for LDAPS (LDAP over implicit TLS)
pub const PORT_LDAPS: u16 = 636;

/// Default port for RDP (Remote Desktop Protocol)
pub const PORT_RDP: u16 = 3389;

/// Default port for MySQL over TLS
pub const PORT_MYSQL: u16 = 3306;

/// Default port for PostgreSQL over TLS
pub const PORT_POSTGRESQL: u16 = 5432;

// =============================================================================
// Buffer Sizes
// =============================================================================

/// Default buffer size for TLS record operations (4 KB)
///
/// This is a reasonable default for most TLS operations and matches
/// common page sizes for efficient memory allocation.
pub const BUFFER_SIZE_DEFAULT: usize = 4096;

/// Maximum TLS record size (16 KB + 2 KB for headers/MAC/padding)
///
/// TLS 1.2 and 1.3 specify a maximum plaintext fragment length of 2^14 bytes
/// (16,384 bytes). With encryption overhead, the maximum record size can be
/// slightly larger.
///
/// Reference: RFC 8446 Section 5.1, RFC 5246 Section 6.2.1
pub const BUFFER_SIZE_MAX_TLS_RECORD: usize = 16384;

/// Maximum allowed TLS record size with overhead
///
/// Includes space for headers, MAC, and padding.
pub const BUFFER_SIZE_MAX_WITH_OVERHEAD: usize = 18432; // 16KB + 2KB overhead

/// Size of TLS random field (32 bytes)
///
/// Used in ClientHello and ServerHello messages.
/// Contains 4 bytes of Unix timestamp + 28 bytes of random data.
///
/// Reference: RFC 8446 Section 4.1.2, RFC 5246 Section 7.4.1.2
pub const RANDOM_BYTES_SIZE: usize = 32;

/// Size of TLS 1.2 and earlier master secret (48 bytes)
///
/// Reference: RFC 5246 Section 8.1
pub const MASTER_SECRET_SIZE: usize = 48;

/// Size of TLS record header (5 bytes)
///
/// Format: [Content Type (1)] [Version (2)] [Length (2)]
///
/// Reference: RFC 8446 Section 5.1, RFC 5246 Section 6.2.1
pub const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Size of handshake message header (4 bytes)
///
/// Format: [Type (1)] [Length (3)]
///
/// Reference: RFC 8446 Section 4, RFC 5246 Section 7.4
pub const HANDSHAKE_HEADER_SIZE: usize = 4;

/// Minimum size for a valid ClientHello message
///
/// Includes record header, handshake header, version, random, session ID length,
/// cipher suite length (minimum 2 bytes), and compression method.
pub const MIN_CLIENT_HELLO_SIZE: usize = 41;

/// Buffer size for reading server responses during vulnerability checks
///
/// Large enough to capture full ServerHello and initial handshake messages.
pub const VULNERABILITY_CHECK_BUFFER_SIZE: usize = 8192;

// =============================================================================
// Timeouts
// =============================================================================

/// Default connection timeout for TCP connections (10 seconds)
///
/// This is a reasonable default that balances responsiveness with
/// tolerance for slow networks.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default read timeout for socket operations (5 seconds)
///
/// Used when waiting for data from a TLS server.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Default write timeout for socket operations (5 seconds)
///
/// Used when sending data to a TLS server.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default socket timeout for general operations (10 seconds)
///
/// General-purpose timeout for socket operations.
pub const DEFAULT_SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// Reduced read timeout for cipher suite testing (3 seconds)
///
/// Faster failure detection during cipher enumeration.
pub const CIPHER_TEST_READ_TIMEOUT: Duration = Duration::from_secs(3);

/// HTTP request timeout for external API calls (30 seconds)
///
/// Used for fetching CT logs, CRLs, and other HTTP-based operations.
pub const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Short timeout for quick probes and fast-fail scenarios (3 seconds)
pub const SHORT_TIMEOUT: Duration = Duration::from_secs(3);

// =============================================================================
// Protocol Versions
// =============================================================================

/// TLS 1.0 version bytes (0x0301)
pub const VERSION_TLS_1_0: u16 = 0x0301;

/// TLS 1.1 version bytes (0x0302)
pub const VERSION_TLS_1_1: u16 = 0x0302;

/// TLS 1.2 version bytes (0x0303)
pub const VERSION_TLS_1_2: u16 = 0x0303;

/// TLS 1.3 version bytes (0x0304)
pub const VERSION_TLS_1_3: u16 = 0x0304;

/// SSL 3.0 version bytes (0x0300)
pub const VERSION_SSL_3_0: u16 = 0x0300;

/// SSL 2.0 version bytes (0x0002)
pub const VERSION_SSL_2_0: u16 = 0x0002;

// =============================================================================
// Compression Methods
// =============================================================================

/// No compression (0x00)
///
/// The only compression method that should be used in modern TLS.
/// CRIME attack demonstrated that compression enables information leakage.
pub const COMPRESSION_NULL: u8 = 0x00;

/// DEFLATE compression (0x01)
///
/// DEPRECATED: Vulnerable to CRIME attack. Should never be used.
///
/// Reference: RFC 3749
pub const COMPRESSION_DEFLATE: u8 = 0x01;

// =============================================================================
// Heartbeat
// =============================================================================

/// Heartbeat request message type
///
/// Reference: RFC 6520
pub const HEARTBEAT_REQUEST: u8 = 0x01;

/// Heartbeat response message type
///
/// Reference: RFC 6520
pub const HEARTBEAT_RESPONSE: u8 = 0x02;

/// Maximum safe heartbeat payload size (recommended)
///
/// Used to avoid triggering IDS and to prevent memory exhaustion.
pub const HEARTBEAT_MAX_PAYLOAD: u16 = 16384;

/// Heartbleed vulnerability test payload size
///
/// The malicious payload size used to detect Heartbleed vulnerability.
/// The vulnerability occurs when the server sends more data than requested.
pub const HEARTBLEED_TEST_PAYLOAD: u16 = 0x4000; // 16384 bytes

// =============================================================================
// Retry and Rate Limiting
// =============================================================================

/// Default delay between retries (3 seconds)
pub const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(3);

/// Maximum number of retry attempts
pub const DEFAULT_MAX_RETRIES: usize = 3;

/// Default rate limit delay for IDS-friendly scanning (100ms)
pub const DEFAULT_RATE_LIMIT_DELAY: Duration = Duration::from_millis(100);

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert content type byte to human-readable string
pub fn content_type_name(content_type: u8) -> &'static str {
    match content_type {
        CONTENT_TYPE_CHANGE_CIPHER_SPEC => "ChangeCipherSpec",
        CONTENT_TYPE_ALERT => "Alert",
        CONTENT_TYPE_HANDSHAKE => "Handshake",
        CONTENT_TYPE_APPLICATION_DATA => "ApplicationData",
        CONTENT_TYPE_HEARTBEAT => "Heartbeat",
        _ => "Unknown",
    }
}

/// Convert handshake type byte to human-readable string
pub fn handshake_type_name(handshake_type: u8) -> &'static str {
    match handshake_type {
        HANDSHAKE_TYPE_HELLO_REQUEST => "HelloRequest",
        HANDSHAKE_TYPE_CLIENT_HELLO => "ClientHello",
        HANDSHAKE_TYPE_SERVER_HELLO => "ServerHello",
        HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST => "HelloVerifyRequest",
        HANDSHAKE_TYPE_NEW_SESSION_TICKET => "NewSessionTicket",
        HANDSHAKE_TYPE_END_OF_EARLY_DATA => "EndOfEarlyData",
        HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => "EncryptedExtensions",
        HANDSHAKE_TYPE_CERTIFICATE => "Certificate",
        HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE => "ServerKeyExchange",
        HANDSHAKE_TYPE_CERTIFICATE_REQUEST => "CertificateRequest",
        HANDSHAKE_TYPE_SERVER_HELLO_DONE => "ServerHelloDone",
        HANDSHAKE_TYPE_CERTIFICATE_VERIFY => "CertificateVerify",
        HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE => "ClientKeyExchange",
        HANDSHAKE_TYPE_FINISHED => "Finished",
        HANDSHAKE_TYPE_CERTIFICATE_URL => "CertificateURL",
        HANDSHAKE_TYPE_CERTIFICATE_STATUS => "CertificateStatus",
        HANDSHAKE_TYPE_KEY_UPDATE => "KeyUpdate",
        HANDSHAKE_TYPE_MESSAGE_HASH => "MessageHash",
        _ => "Unknown",
    }
}

/// Convert protocol version to human-readable string
pub fn protocol_version_name(version: u16) -> &'static str {
    match version {
        VERSION_SSL_2_0 => "SSL 2.0",
        VERSION_SSL_3_0 => "SSL 3.0",
        VERSION_TLS_1_0 => "TLS 1.0",
        VERSION_TLS_1_1 => "TLS 1.1",
        VERSION_TLS_1_2 => "TLS 1.2",
        VERSION_TLS_1_3 => "TLS 1.3",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_names() {
        assert_eq!(content_type_name(0x16), "Handshake");
        assert_eq!(content_type_name(0x15), "Alert");
        assert_eq!(content_type_name(0x17), "ApplicationData");
        assert_eq!(content_type_name(0x14), "ChangeCipherSpec");
        assert_eq!(content_type_name(0x18), "Heartbeat");
        assert_eq!(content_type_name(0xFF), "Unknown");
    }

    #[test]
    fn test_handshake_type_names() {
        assert_eq!(handshake_type_name(0x01), "ClientHello");
        assert_eq!(handshake_type_name(0x02), "ServerHello");
        assert_eq!(handshake_type_name(0x0B), "Certificate");
        assert_eq!(handshake_type_name(0x14), "Finished");
        assert_eq!(handshake_type_name(0xFF), "Unknown");
    }

    #[test]
    fn test_protocol_version_names() {
        assert_eq!(protocol_version_name(0x0301), "TLS 1.0");
        assert_eq!(protocol_version_name(0x0302), "TLS 1.1");
        assert_eq!(protocol_version_name(0x0303), "TLS 1.2");
        assert_eq!(protocol_version_name(0x0304), "TLS 1.3");
        assert_eq!(protocol_version_name(0x0300), "SSL 3.0");
        assert_eq!(protocol_version_name(0xFFFF), "Unknown");
    }

    #[test]
    fn test_buffer_sizes() {
        assert_eq!(BUFFER_SIZE_DEFAULT, 4096);
        assert_eq!(BUFFER_SIZE_MAX_TLS_RECORD, 16384);
        assert_eq!(RANDOM_BYTES_SIZE, 32);
        assert_eq!(TLS_RECORD_HEADER_SIZE, 5);
        assert_eq!(HANDSHAKE_HEADER_SIZE, 4);
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(PORT_HTTPS, 443);
        assert_eq!(PORT_SMTP, 25);
        assert_eq!(PORT_SMTPS, 465);
        assert_eq!(PORT_SMTP_SUBMISSION, 587);
        assert_eq!(PORT_IMAPS, 993);
        assert_eq!(PORT_POP3S, 995);
    }

    #[test]
    fn test_timeouts() {
        assert_eq!(DEFAULT_CONNECT_TIMEOUT, Duration::from_secs(10));
        assert_eq!(DEFAULT_READ_TIMEOUT, Duration::from_secs(5));
        assert_eq!(CIPHER_TEST_READ_TIMEOUT, Duration::from_secs(3));
    }
}
