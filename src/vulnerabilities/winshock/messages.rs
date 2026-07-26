pub(super) fn malformed_client_key_exchange() -> Vec<u8> {
    let mut msg = vec![
        0x16, 0x03, 0x03, // TLS Record: Handshake (TLS 1.2)
        0xff, 0xff, // Malformed length
        0x10, // Handshake: ClientKeyExchange
        0xff, 0xff, 0xff, // Malformed handshake length
        0xff, 0xff, // Encrypted PMS with malformed length
    ];

    msg.extend_from_slice(&[0x41; 256]);
    msg
}
