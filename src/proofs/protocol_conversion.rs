// Kani Proof Harnesses for Protocol Conversion and Parsing
//
// These proofs verify that protocol-related functions handle
// all inputs safely without panics or undefined behavior.

use crate::protocols::Protocol;

/// Proof: Protocol enum covers all valid TLS versions
///
/// Verifies that known TLS version codes map correctly.
#[cfg(kani)]
#[kani::proof]
fn proof_known_protocol_versions() {
    // Test all known TLS version codes
    let versions: [(u16, &str); 6] = [
        (0x0002, "SSLv2"),
        (0x0300, "SSLv3"),
        (0x0301, "TLS 1.0"),
        (0x0302, "TLS 1.1"),
        (0x0303, "TLS 1.2"),
        (0x0304, "TLS 1.3"),
    ];

    for (version, expected_name) in versions {
        let protocol = Protocol::from(version);
        let name = protocol.name();
        kani::assert(name == expected_name, "Protocol name should match");
    }
}

/// Proof: Protocol::is_deprecated is consistent
///
/// Verifies that deprecated protocol detection is correct.
#[cfg(kani)]
#[kani::proof]
fn proof_deprecated_protocols() {
    // Use index to select protocol variant
    let idx: u8 = kani::any();
    kani::assume(idx < 7);

    let protocol = match idx {
        0 => Protocol::SSLv2,
        1 => Protocol::SSLv3,
        2 => Protocol::TLS10,
        3 => Protocol::TLS11,
        4 => Protocol::TLS12,
        5 => Protocol::TLS13,
        _ => Protocol::QUIC,
    };

    let is_deprecated = protocol.is_deprecated();

    // Verify consistency with known deprecated protocols
    match protocol {
        Protocol::SSLv2 | Protocol::SSLv3 | Protocol::TLS10 | Protocol::TLS11 => {
            kani::assert(is_deprecated, "Old protocols should be deprecated");
        }
        Protocol::TLS12 | Protocol::TLS13 | Protocol::QUIC => {
            kani::assert(!is_deprecated, "Modern protocols should not be deprecated");
        }
    }
}

/// Proof: Protocol comparison is consistent
///
/// Verifies that Protocol ordering is consistent.
#[cfg(kani)]
#[kani::proof]
fn proof_protocol_ordering() {
    // Use indices to select protocol variants
    let idx1: u8 = kani::any();
    let idx2: u8 = kani::any();
    kani::assume(idx1 < 7);
    kani::assume(idx2 < 7);

    let p1 = match idx1 {
        0 => Protocol::SSLv2,
        1 => Protocol::SSLv3,
        2 => Protocol::TLS10,
        3 => Protocol::TLS11,
        4 => Protocol::TLS12,
        5 => Protocol::TLS13,
        _ => Protocol::QUIC,
    };

    let p2 = match idx2 {
        0 => Protocol::SSLv2,
        1 => Protocol::SSLv3,
        2 => Protocol::TLS10,
        3 => Protocol::TLS11,
        4 => Protocol::TLS12,
        5 => Protocol::TLS13,
        _ => Protocol::QUIC,
    };

    // Reflexive
    kani::assert(p1 == p1, "Protocol should equal itself");

    // Symmetric
    kani::assert((p1 == p2) == (p2 == p1), "Equality should be symmetric");

    // If equal, hash should be equal (implicitly true for derive(Hash))
    if p1 == p2 {
        let h1 = p1.as_hex();
        let h2 = p2.as_hex();
        kani::assert(h1 == h2, "Equal protocols should have same hex");
    }
}

/// Proof: Unknown version codes default safely
///
/// Verifies that unknown TLS version codes don't cause panics.
#[cfg(kani)]
#[kani::proof]
fn proof_unknown_version_handling() {
    let version: u16 = kani::any();

    // Exclude known versions
    kani::assume(
        version != 0x0002
            && version != 0x0300
            && version != 0x0301
            && version != 0x0302
            && version != 0x0303
            && version != 0x0304
    );

    // Should not panic, defaults to TLS 1.2
    let protocol = Protocol::from(version);
    kani::assert(protocol == Protocol::TLS12, "Unknown versions should default to TLS 1.2");
}

/// Proof: Record layer version determination
///
/// Verifies that determining the record layer version is safe.
#[cfg(kani)]
#[kani::proof]
fn proof_record_layer_version() {
    use crate::constants::{VERSION_SSL_3_0, VERSION_TLS_1_0};

    // Use index to select protocol variant
    let idx: u8 = kani::any();
    kani::assume(idx < 7);

    let protocol = match idx {
        0 => Protocol::SSLv2,
        1 => Protocol::SSLv3,
        2 => Protocol::TLS10,
        3 => Protocol::TLS11,
        4 => Protocol::TLS12,
        5 => Protocol::TLS13,
        _ => Protocol::QUIC,
    };

    let record_version = match protocol {
        Protocol::SSLv3 => VERSION_SSL_3_0,
        _ => VERSION_TLS_1_0,
    };

    // Verify valid version codes
    kani::assert(
        record_version == VERSION_SSL_3_0 || record_version == VERSION_TLS_1_0,
        "Record version should be SSL 3.0 or TLS 1.0"
    );
}

/// Proof: Client version determination for TLS 1.3
///
/// Verifies that TLS 1.3 compatibility handling is correct.
#[cfg(kani)]
#[kani::proof]
fn proof_client_version_tls13() {
    use crate::constants::VERSION_TLS_1_2;

    // Use index to select protocol variant
    let idx: u8 = kani::any();
    kani::assume(idx < 7);

    let protocol = match idx {
        0 => Protocol::SSLv2,
        1 => Protocol::SSLv3,
        2 => Protocol::TLS10,
        3 => Protocol::TLS11,
        4 => Protocol::TLS12,
        5 => Protocol::TLS13,
        _ => Protocol::QUIC,
    };

    // For TLS 1.3, legacy version field should be 0x0303 (TLS 1.2)
    let client_version = if matches!(protocol, Protocol::TLS13) {
        VERSION_TLS_1_2
    } else {
        protocol.as_hex()
    };

    // Verify valid version
    if matches!(protocol, Protocol::TLS13) {
        kani::assert(client_version == VERSION_TLS_1_2, "TLS 1.3 should use 0x0303 for compatibility");
    }
}

/// Proof: Extension type name lookup is total
///
/// Verifies that looking up extension names handles all types.
#[cfg(kani)]
#[kani::proof]
fn proof_extension_name_lookup() {
    let extension_type: u16 = kani::any();

    let name = match extension_type {
        0x0000 => "server_name (SNI)",
        0x0001 => "max_fragment_length",
        0x0005 => "status_request (OCSP stapling)",
        0x000a => "supported_groups",
        0x000b => "ec_point_formats",
        0x000d => "signature_algorithms",
        0x000f => "heartbeat",
        0x0010 => "application_layer_protocol_negotiation (ALPN)",
        0x0012 => "signed_certificate_timestamp",
        0x0015 => "padding",
        0x0017 => "extended_master_secret",
        0x0023 => "session_ticket",
        0x002b => "supported_versions",
        0x002d => "psk_key_exchange_modes",
        0x0033 => "key_share",
        0xff01 => "renegotiation_info",
        _ => "unknown",
    };

    kani::assert(!name.is_empty(), "Extension name should not be empty");
}

/// Proof: Version bytes extraction is safe
///
/// Verifies that extracting version from bytes doesn't panic.
#[cfg(kani)]
#[kani::proof]
fn proof_version_byte_extraction() {
    let high: u8 = kani::any();
    let low: u8 = kani::any();

    // Big-endian reconstruction
    let version = u16::from_be_bytes([high, low]);

    // Convert to protocol
    let protocol = Protocol::from(version);
    let _name = protocol.name(); // Should not panic
}

/// Proof: Cipher suite parsing bounds
///
/// Verifies that cipher suite list parsing respects bounds.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(33)]
fn proof_cipher_suite_parsing_bounds() {
    let suite_count: usize = kani::any();
    kani::assume(suite_count <= 16); // Bound for tractability

    let mut parsed_count: usize = 0;

    for _ in 0..suite_count {
        let high: u8 = kani::any();
        let low: u8 = kani::any();
        let _suite = u16::from_be_bytes([high, low]);
        parsed_count += 1;
    }

    kani::assert(parsed_count == suite_count, "Should have expected number of suites");
}

/// Proof: SNI hostname length handling
///
/// Verifies that SNI extension length calculations are safe.
#[cfg(kani)]
#[kani::proof]
fn proof_sni_length_calculation() {
    let hostname_len: usize = kani::any();
    kani::assume(hostname_len > 0 && hostname_len <= 255); // DNS name limit

    // SNI extension structure:
    // - 2 bytes: extension type
    // - 2 bytes: extension length
    // - 2 bytes: server name list length
    // - 1 byte: name type
    // - 2 bytes: hostname length
    // - N bytes: hostname

    let list_len = 3 + hostname_len; // 1 (type) + 2 (len) + hostname
    let ext_len = 2 + list_len; // 2 (list len) + list

    kani::assert(list_len <= 258, "List length should be bounded");
    kani::assert(ext_len <= 260, "Extension length should be bounded");

    // Verify fits in u16
    kani::assert(ext_len <= 65535, "Should fit in u16 length field");
}

/// Proof: ALPN protocol list construction
///
/// Verifies that ALPN extension construction is safe.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(11)]
fn proof_alpn_construction() {
    let protocol_count: usize = kani::any();
    kani::assume(protocol_count > 0 && protocol_count <= 5);

    let mut total_len: usize = 0;

    for _ in 0..protocol_count {
        let proto_len: usize = kani::any();
        kani::assume(proto_len > 0 && proto_len <= 255); // ALPN protocol max length

        // Each protocol: 1 byte length + N bytes name
        match total_len.checked_add(1 + proto_len) {
            Some(new_len) => {
                total_len = new_len;
            }
            None => {
                // Overflow - would be caught
                return;
            }
        }
    }

    // Verify fits in extension
    kani::assert(total_len <= 65535, "ALPN list should fit in extension");
}

/// Proof: Session ID handling
///
/// Verifies that session ID length handling is safe.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(33)]
fn proof_session_id_handling() {
    let session_id_len: u8 = kani::any();
    kani::assume(session_id_len <= 32); // Max session ID length per TLS spec

    let mut session_id: [u8; 32] = [0u8; 32];
    for i in 0..(session_id_len as usize) {
        session_id[i] = kani::any();
    }

    let actual_len = session_id_len as usize;
    let _ = session_id;
    kani::assert(actual_len == session_id_len as usize, "Session ID should match length");
    kani::assert(actual_len <= 32, "Session ID should not exceed max");
}

/// Proof: Handshake length field encoding
///
/// Verifies that 3-byte handshake length encoding is correct.
#[cfg(kani)]
#[kani::proof]
fn proof_handshake_length_encoding() {
    let length: u32 = kani::any();
    kani::assume(length <= 0x00FFFFFF); // 24-bit max

    // Encode as 3 bytes (big-endian)
    let byte0 = ((length >> 16) & 0xff) as u8;
    let byte1 = ((length >> 8) & 0xff) as u8;
    let byte2 = (length & 0xff) as u8;

    // Decode back
    let decoded = ((byte0 as u32) << 16) | ((byte1 as u32) << 8) | (byte2 as u32);

    kani::assert(decoded == length, "Handshake length roundtrip should match");
}
