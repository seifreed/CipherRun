// TLS record construction for POODLE variant testing
//
// Builds deliberately malformed TLS records with different padding/MAC
// combinations for oracle detection.

use crate::constants::{CONTENT_TYPE_APPLICATION_DATA, VERSION_TLS_1_2};
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;

use super::MalformedRecordType;

/// Build ClientHello with CBC cipher preference using ClientHelloBuilder
pub(super) fn build_client_hello_cbc() -> Vec<u8> {
    let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
    builder.for_cbc_ciphers();
    builder.build_minimal().unwrap_or_else(|_| Vec::new())
}

/// Build malformed TLS record based on type
pub(super) fn build_malformed_record(record_type: MalformedRecordType) -> Vec<u8> {
    match record_type {
        MalformedRecordType::InvalidPaddingValidMac => build_record_invalid_padding_valid_mac(),
        MalformedRecordType::ValidPaddingInvalidMac => build_record_valid_padding_invalid_mac(),
        MalformedRecordType::InvalidPaddingInvalidMac => build_record_invalid_padding_invalid_mac(),
        MalformedRecordType::ZeroLengthFragment => build_zero_length_record(),
    }
}

/// Build record with invalid padding but valid MAC structure
pub(super) fn build_record_invalid_padding_valid_mac() -> Vec<u8> {
    let mut record = tls_app_data_header(0x37); // 55 bytes (32 data + 16 MAC + 7 padding)

    // Encrypted data (32 bytes)
    record.extend_from_slice(&[0x41; 32]);

    // MAC (16 bytes - simulated valid structure)
    record.extend_from_slice(&[0x00; 16]);

    // Invalid padding: inconsistent bytes (should all be same value)
    for i in 0..7 {
        record.push((i * 3) as u8);
    }

    record
}

/// Build record with valid padding but invalid MAC
pub(super) fn build_record_valid_padding_invalid_mac() -> Vec<u8> {
    let mut record = tls_app_data_header(0x37); // 55 bytes

    // Encrypted data (32 bytes)
    record.extend_from_slice(&[0x41; 32]);

    // Invalid MAC (16 bytes - all 0xFF)
    record.extend_from_slice(&[0xff; 16]);

    // Valid padding: PKCS#7 - 7 bytes of 0x06
    record.extend(std::iter::repeat_n(0x06, 7));

    record
}

/// Build record with both invalid padding and invalid MAC
pub(super) fn build_record_invalid_padding_invalid_mac() -> Vec<u8> {
    let mut record = tls_app_data_header(0x37); // 55 bytes

    // Encrypted data (32 bytes)
    record.extend_from_slice(&[0x41; 32]);

    // Invalid MAC (16 bytes)
    record.extend_from_slice(&[0xff; 16]);

    // Invalid padding
    for i in 0..7 {
        record.push((i * 5) as u8);
    }

    record
}

/// Build zero-length TLS fragment
pub(super) fn build_zero_length_record() -> Vec<u8> {
    tls_app_data_header(0x00) // 0 bytes payload
}

/// Construct the common TLS Application Data record header
fn tls_app_data_header(length_lsb: u8) -> Vec<u8> {
    vec![
        CONTENT_TYPE_APPLICATION_DATA,  // Application Data (0x17)
        (VERSION_TLS_1_2 >> 8) as u8,   // TLS 1.2 (0x03)
        (VERSION_TLS_1_2 & 0xff) as u8, // (0x03)
        0x00,
        length_lsb,
    ]
}
