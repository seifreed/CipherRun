use ring::digest::{SHA256, digest};

const ZERO_HASH: &str = "00000000000000000000000000000000000000000000000000000000000000";
const JARM_PROBE_COUNT: usize = 10;

pub(super) fn raw_hash_to_fuzzy_hash(raw: &str) -> String {
    if raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||" {
        return ZERO_HASH.to_string();
    }

    let handshakes: Vec<&str> = raw.split(',').collect();
    if handshakes.len() != JARM_PROBE_COUNT {
        tracing::warn!(
            event_name = "fingerprint.jarm.input.invalid",
            expected_probe_count = JARM_PROBE_COUNT,
            actual_probe_count = handshakes.len(),
            "JARM input has an unexpected probe response count"
        );
        return ZERO_HASH.to_string();
    }

    let mut fhash = String::new();
    let mut alpex = String::new();
    for handshake in handshakes {
        let mut comp = handshake.split('|');
        let (Some(cipher), Some(version), Some(alpn), Some(extensions), None) = (
            comp.next(),
            comp.next(),
            comp.next(),
            comp.next(),
            comp.next(),
        ) else {
            return ZERO_HASH.to_string();
        };

        fhash.push_str(&extract_cipher_bytes(cipher));
        fhash.push_str(&extract_version_byte(version));
        alpex.push_str(alpn);
        alpex.push_str(extensions);
    }

    let hash_result = digest(&SHA256, alpex.as_bytes());
    let hash_hex = hex::encode(hash_result.as_ref());
    fhash.push_str(hash_hex.get(..32).unwrap_or(&hash_hex));
    fhash
}

const CIPHER_LIST_ORDER: &[[u8; 2]] = &[
    [0x00, 0x04],
    [0x00, 0x05],
    [0x00, 0x07],
    [0x00, 0x0a],
    [0x00, 0x16],
    [0x00, 0x2f],
    [0x00, 0x33],
    [0x00, 0x35],
    [0x00, 0x39],
    [0x00, 0x3c],
    [0x00, 0x3d],
    [0x00, 0x41],
    [0x00, 0x45],
    [0x00, 0x67],
    [0x00, 0x6b],
    [0x00, 0x84],
    [0x00, 0x88],
    [0x00, 0x9a],
    [0x00, 0x9c],
    [0x00, 0x9d],
    [0x00, 0x9e],
    [0x00, 0x9f],
    [0x00, 0xba],
    [0x00, 0xbe],
    [0x00, 0xc0],
    [0x00, 0xc4],
    [0xc0, 0x07],
    [0xc0, 0x08],
    [0xc0, 0x09],
    [0xc0, 0x0a],
    [0xc0, 0x11],
    [0xc0, 0x12],
    [0xc0, 0x13],
    [0xc0, 0x14],
    [0xc0, 0x23],
    [0xc0, 0x24],
    [0xc0, 0x27],
    [0xc0, 0x28],
    [0xc0, 0x2b],
    [0xc0, 0x2c],
    [0xc0, 0x2f],
    [0xc0, 0x30],
    [0xc0, 0x60],
    [0xc0, 0x61],
    [0xc0, 0x72],
    [0xc0, 0x73],
    [0xc0, 0x76],
    [0xc0, 0x77],
    [0xc0, 0x9c],
    [0xc0, 0x9d],
    [0xc0, 0x9e],
    [0xc0, 0x9f],
    [0xc0, 0xa0],
    [0xc0, 0xa1],
    [0xc0, 0xa2],
    [0xc0, 0xa3],
    [0xc0, 0xac],
    [0xc0, 0xad],
    [0xc0, 0xae],
    [0xc0, 0xaf],
    [0xcc, 0x13],
    [0xcc, 0x14],
    [0xcc, 0xa8],
    [0xcc, 0xa9],
    [0x13, 0x01],
    [0x13, 0x02],
    [0x13, 0x03],
    [0x13, 0x04],
    [0x13, 0x05],
];

fn extract_cipher_bytes(cipher_hex: &str) -> String {
    if cipher_hex.is_empty() {
        return "00".to_string();
    }

    let cipher_bytes = match hex::decode(cipher_hex) {
        Ok(bytes) => match <[u8; 2]>::try_from(bytes.as_slice()) {
            Ok(bytes) => bytes,
            Err(_) => return "00".to_string(),
        },
        _ => return "00".to_string(),
    };

    for (i, known_cipher) in CIPHER_LIST_ORDER.iter().enumerate() {
        if known_cipher == &cipher_bytes {
            return format!("{:02x}", i + 1);
        }
    }

    // Off-list ciphers use the canonical post-loop counter; "00" is only no-cipher.
    format!("{:02x}", CIPHER_LIST_ORDER.len() + 1)
}

fn extract_version_byte(version_hex: &str) -> String {
    if version_hex.len() < 4 {
        return "0".to_string();
    }

    version_hex
        .chars()
        .nth(3)
        .and_then(|c| c.to_digit(16))
        .and_then(|val| char::from_u32(0x61 + val))
        .map(|ch| ch.to_string())
        .unwrap_or_else(|| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_hash_for_all_failed_probes() {
        let raw = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||";
        assert_eq!(raw_hash_to_fuzzy_hash(raw), ZERO_HASH);
    }

    #[test]
    fn hashes_ten_well_formed_probe_responses() {
        let raw = ["c02f|0303|h2|ext"; JARM_PROBE_COUNT].join(",");
        let hash = raw_hash_to_fuzzy_hash(&raw);

        assert_eq!(&hash[..30], "29d".repeat(JARM_PROBE_COUNT));
        assert_eq!(hash.len(), 62);
        assert_eq!(raw_hash_to_fuzzy_hash(&raw), hash);
    }

    #[test]
    fn rejects_unexpected_counts_and_malformed_probe_fields() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        struct Buffer(Arc<Mutex<Vec<u8>>>);
        struct BufferWriter(Arc<Mutex<Vec<u8>>>);

        impl Write for BufferWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for Buffer {
            type Writer = BufferWriter;

            fn make_writer(&'a self) -> Self::Writer {
                BufferWriter(self.0.clone())
            }
        }

        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_writer(Buffer(output.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            assert_eq!(raw_hash_to_fuzzy_hash("not-ten-probes"), ZERO_HASH);
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["level"], "WARN");
        assert_eq!(
            event["fields"]["event_name"],
            "fingerprint.jarm.input.invalid"
        );
        assert_eq!(event["fields"]["expected_probe_count"], JARM_PROBE_COUNT);
        assert_eq!(event["fields"]["actual_probe_count"], 1);

        let mut probes = ["c02f|0303|h2|ext"; JARM_PROBE_COUNT];
        probes[4] = "c02f|0303|h2|ext|extra";
        assert_eq!(raw_hash_to_fuzzy_hash(&probes.join(",")), ZERO_HASH);

        probes[4] = "c02f|0303|h2";
        assert_eq!(raw_hash_to_fuzzy_hash(&probes.join(",")), ZERO_HASH);
    }

    #[test]
    fn cipher_extraction_uses_jarm_index_encoding() {
        assert_eq!(extract_cipher_bytes("c02f"), "29");
        assert_eq!(extract_cipher_bytes("1301"), "41");
        assert_eq!(extract_cipher_bytes(""), "00");
        assert_eq!(extract_cipher_bytes("01"), "00");
        assert_eq!(extract_cipher_bytes("not-hex"), "00");
        assert_eq!(extract_cipher_bytes("ffff"), "46");
    }

    #[test]
    fn version_extraction_uses_last_version_nibble() {
        assert_eq!(extract_version_byte("0303"), "d");
        assert_eq!(extract_version_byte("0304"), "e");
        assert_eq!(extract_version_byte("0301"), "b");
        assert_eq!(extract_version_byte(""), "0");
        assert_eq!(extract_version_byte("03zz"), "0");
    }
}
