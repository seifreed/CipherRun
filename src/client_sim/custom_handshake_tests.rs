use super::*;

fn sample_profile(highest_protocol: Option<&str>) -> ClientProfile {
    ClientProfile {
        name: "Test Client".to_string(),
        short_id: "test".to_string(),
        cipher_string: None,
        tls13_ciphers: None,
        uses_sni: true,
        warning: None,
        handshake_bytes: None,
        protocol_flags: vec![],
        tls_version: None,
        lowest_protocol: None,
        highest_protocol: highest_protocol.map(|s| s.to_string()),
        services: vec![],
        min_dh_bits: None,
        max_dh_bits: None,
        min_rsa_bits: None,
        max_rsa_bits: None,
        min_ecdsa_bits: None,
        curves: vec![],
        requires_sha2: false,
        current: true,
    }
}

fn build_server_hello(
    cipher: u16,
    alpn: Option<&str>,
    selected_version: Option<u16>,
    key_share_group: Option<u16>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x02); // ServerHello
    body.extend_from_slice(&[0x00, 0x00, 0x00]); // Handshake length placeholder
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 in legacy_version
    body.extend_from_slice(&[0u8; 32]); // Random
    body.push(0x00); // Session ID length
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0x00); // Compression method

    let mut extensions = Vec::new();
    if let Some(proto) = alpn {
        let proto_bytes = proto.as_bytes();
        let list_len = proto_bytes.len() + 1;
        let ext_len = 2 + list_len;
        extensions.extend_from_slice(&0x0010u16.to_be_bytes());
        extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(list_len as u16).to_be_bytes());
        extensions.push(proto_bytes.len() as u8);
        extensions.extend_from_slice(proto_bytes);
    }

    if let Some(version) = selected_version {
        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&2u16.to_be_bytes());
        extensions.extend_from_slice(&version.to_be_bytes());
    }

    if let Some(group) = key_share_group {
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&2u16.to_be_bytes());
        extensions.extend_from_slice(&group.to_be_bytes());
    }

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let hs_len = body.len() - 4;
    body[1] = ((hs_len >> 16) & 0xff) as u8;
    body[2] = ((hs_len >> 8) & 0xff) as u8;
    body[3] = (hs_len & 0xff) as u8;

    let mut record = vec![0x16, 0x03, 0x03, 0x00, 0x00];
    let record_len = body.len();
    record[3] = ((record_len >> 8) & 0xff) as u8;
    record[4] = (record_len & 0xff) as u8;
    record.extend_from_slice(&body);
    record
}

fn parse_extension_types(client_hello: &[u8]) -> Vec<u16> {
    let session_len = client_hello[43] as usize;
    let cipher_len_pos = 44 + session_len;
    let cipher_len = u16::from_be_bytes([
        client_hello[cipher_len_pos],
        client_hello[cipher_len_pos + 1],
    ]) as usize;
    let compression_len_pos = cipher_len_pos + 2 + cipher_len;
    let compression_len = client_hello[compression_len_pos] as usize;
    let extensions_len_pos = compression_len_pos + 1 + compression_len;
    let extensions_len = u16::from_be_bytes([
        client_hello[extensions_len_pos],
        client_hello[extensions_len_pos + 1],
    ]) as usize;
    let mut pos = extensions_len_pos + 2;
    let end = pos + extensions_len;
    let mut extension_types = Vec::new();

    while pos + 4 <= end {
        let extension_type = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
        let extension_len =
            u16::from_be_bytes([client_hello[pos + 2], client_hello[pos + 3]]) as usize;
        extension_types.push(extension_type);
        pos += 4 + extension_len;
    }

    extension_types
}

fn supported_groups_from_client_hello(client_hello: &[u8]) -> Vec<u16> {
    let session_len = client_hello[43] as usize;
    let cipher_len_pos = 44 + session_len;
    let cipher_len = u16::from_be_bytes([
        client_hello[cipher_len_pos],
        client_hello[cipher_len_pos + 1],
    ]) as usize;
    let compression_len_pos = cipher_len_pos + 2 + cipher_len;
    let compression_len = client_hello[compression_len_pos] as usize;
    let extensions_len_pos = compression_len_pos + 1 + compression_len;
    let extensions_len = u16::from_be_bytes([
        client_hello[extensions_len_pos],
        client_hello[extensions_len_pos + 1],
    ]) as usize;
    let mut pos = extensions_len_pos + 2;
    let end = pos + extensions_len;

    while pos + 4 <= end {
        let extension_type = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
        let extension_len =
            u16::from_be_bytes([client_hello[pos + 2], client_hello[pos + 3]]) as usize;
        let data_start = pos + 4;
        let data_end = data_start + extension_len;
        if extension_type == 0x000a && data_start + 2 <= data_end {
            let list_len =
                u16::from_be_bytes([client_hello[data_start], client_hello[data_start + 1]])
                    as usize;
            let mut group_pos = data_start + 2;
            let group_end = (group_pos + list_len).min(data_end);
            let mut groups = Vec::new();
            while group_pos + 2 <= group_end {
                groups.push(u16::from_be_bytes([
                    client_hello[group_pos],
                    client_hello[group_pos + 1],
                ]));
                group_pos += 2;
            }
            return groups;
        }
        pos = data_end;
    }

    Vec::new()
}

#[test]
fn test_sni_extension() {
    let ext = TlsExtension::server_name("example.com");
    assert_eq!(ext.extension_type, 0x0000);
    let encoded = ext.encode();
    assert!(encoded.len() > 4);
}

#[test]
fn test_extension_encodings() {
    let groups = TlsExtension::supported_groups(&[0x001d, 0x0017]);
    let groups_encoded = groups.encode();
    assert_eq!(groups.extension_type, 0x000a);
    assert_eq!(groups_encoded[4], 0x00);
    assert_eq!(groups_encoded[5], 0x04);

    let sigs = TlsExtension::signature_algorithms(&[(0x04, 0x03), (0x08, 0x04)]);
    let sigs_encoded = sigs.encode();
    assert_eq!(sigs.extension_type, 0x000d);
    assert_eq!(sigs_encoded[4], 0x00);
    assert_eq!(sigs_encoded[5], 0x04);

    let alpn = TlsExtension::alpn(&["h2", "http/1.1"]);
    let alpn_encoded = alpn.encode();
    assert_eq!(alpn.extension_type, 0x0010);
    assert!(alpn_encoded.len() > 8);

    let versions = TlsExtension::supported_versions(&[0x0304, 0x0303]);
    let versions_encoded = versions.encode();
    assert_eq!(versions.extension_type, 0x002b);
    assert_eq!(versions_encoded[4], 0x04);
}

#[test]
fn test_client_hello_builder() {
    let hello = ClientHelloBuilder::new(0x0303)
        .cipher_suite(0xc02f)
        .cipher_suite(0xc030)
        .extension(TlsExtension::server_name("test.com"))
        .build();

    assert_eq!(hello[0], 0x16); // Handshake record
    assert_eq!(hello[5], 0x01); // ClientHello
    assert!(hello.len() > 50);
}

#[test]
fn test_client_hello_from_profile_tls13() {
    let profile = sample_profile(Some("tls1_3"));
    let hello = ClientHelloBuilder::from_profile(&profile, "example.com").build();

    assert_eq!(hello[0], 0x16); // Handshake
    assert_eq!(hello[5], 0x01); // ClientHello
    assert!(hello.windows(2).any(|w| w == [0x00, 0x2b])); // supported_versions
    assert!(hello.windows(2).any(|w| w == [0x00, 0x10])); // ALPN
}

#[test]
fn test_client_hello_from_profile_omits_sni_when_profile_disables_it() {
    let mut profile = sample_profile(Some("tls1_2"));
    profile.uses_sni = false;

    let hello = ClientHelloBuilder::from_profile(&profile, "example.com").build();
    let extension_types = parse_extension_types(&hello);

    assert!(!extension_types.contains(&0x0000));
}

#[test]
fn test_client_hello_from_profile_uses_profile_curves() {
    let mut profile = sample_profile(Some("tls1_2"));
    profile.curves = vec!["secp256r1".to_string(), "secp384r1".to_string()];

    let hello = ClientHelloBuilder::from_profile(&profile, "example.com").build();

    assert_eq!(supported_groups_from_client_hello(&hello), [0x0017, 0x0018]);
}

#[test]
fn test_parse_server_hello_extended_with_alpn() {
    let data = build_server_hello(0x1301, Some("h2"), Some(0x0304), Some(0x001d));
    let info = parse_server_hello_extended(&data).expect("test assertion should succeed");

    assert_eq!(info.protocol, Protocol::TLS13);
    assert_eq!(info.cipher, "TLS_AES_128_GCM_SHA256");
    assert_eq!(info.alpn.as_deref(), Some("h2"));
    assert_eq!(info.key_exchange_group, Some(0x001d));
}

#[test]
fn test_parse_server_hello_rejects_unknown_legacy_version() {
    let mut data = build_server_hello(0x1301, None, None, None);
    data[9] = 0x7f;
    data[10] = 0x17;

    let err = parse_server_hello_extended(&data).expect_err("unknown version should fail");

    assert!(
        err.to_string()
            .contains("Unknown ServerHello protocol version")
    );
}

#[test]
fn test_parse_server_hello_extended_missing() {
    let err = parse_server_hello_extended(&[0x00, 0x01, 0x02]).unwrap_err();
    let message = format!("{err}");
    assert!(message.contains("ServerHello") || message.contains("handshake"));
}

#[test]
fn test_format_cipher_name_unknown() {
    let name = format_cipher_name(0x1234);
    assert_eq!(name, "0x1234");
}
