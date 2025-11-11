// JARM probe builder - constructs the 10 TLS Client Hello packets for JARM fingerprinting
//
// JARM sends 10 different Client Hello probes with varying configurations:
// - Different TLS versions (1.1, 1.2, 1.3)
// - Different cipher orderings (FORWARD, REVERSE, TOP_HALF, BOTTOM_HALF, MIDDLE_OUT)
// - With/without GREASE
// - Different ALPN configurations
// - Different extension orders

use rand::Rng;

/// JARM probe options
#[derive(Debug, Clone)]
pub struct JarmProbeOptions {
    pub hostname: String,
    pub port: u16,
    pub version: TlsVersion,
    pub cipher_list: CipherList,
    pub cipher_order: CipherOrder,
    pub grease: bool,
    pub alpn: AlpnMode,
    pub v13_mode: V13Mode,
    pub extension_order: ExtensionOrder,
}

/// JARM probe (built Client Hello packet)
#[derive(Debug, Clone)]
pub struct JarmProbe {
    pub options: JarmProbeOptions,
    packet: Vec<u8>,
}

impl JarmProbe {
    /// Build the probe packet
    pub fn build(&self) -> Vec<u8> {
        self.packet.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    SSL30 = 0x0300,
    TLS10 = 0x0301,
    TLS11 = 0x0302,
    TLS12 = 0x0303,
    TLS13 = 0x0304,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherList {
    All,
    No13, // All ciphers except TLS 1.3
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherOrder {
    Forward,
    Reverse,
    TopHalf,
    BottomHalf,
    MiddleOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnMode {
    Alpn,     // Standard ALPN list
    RareAlpn, // Rare ALPN protocols (no h2/http1.1)
    NoSupport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V13Mode {
    Support13,     // TLS 1.3 in supported_versions
    Support12Only, // Only up to TLS 1.2
    NoSupport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionOrder {
    Forward,
    Reverse,
}

/// Get the standard 10 JARM probes
pub fn get_probes(hostname: &str, port: u16) -> Vec<JarmProbe> {
    vec![
        // Probe 1: TLS 1.2, ALL ciphers, FORWARD order, NO_GREASE, ALPN, 1.2 support, REVERSE extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS12,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::Forward,
            grease: false,
            alpn: AlpnMode::Alpn,
            v13_mode: V13Mode::Support12Only,
            extension_order: ExtensionOrder::Reverse,
        }),
        // Probe 2: TLS 1.2, ALL ciphers, REVERSE order, NO_GREASE, ALPN, 1.2 support, FORWARD extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS12,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::Reverse,
            grease: false,
            alpn: AlpnMode::Alpn,
            v13_mode: V13Mode::Support12Only,
            extension_order: ExtensionOrder::Forward,
        }),
        // Probe 3: TLS 1.2, ALL ciphers, TOP_HALF order, NO_GREASE, NO_ALPN, NO 1.3, FORWARD extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS12,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::TopHalf,
            grease: false,
            alpn: AlpnMode::NoSupport,
            v13_mode: V13Mode::NoSupport,
            extension_order: ExtensionOrder::Forward,
        }),
        // Probe 4: TLS 1.2, ALL ciphers, BOTTOM_HALF order, NO_GREASE, RARE_ALPN, NO 1.3, FORWARD extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS12,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::BottomHalf,
            grease: false,
            alpn: AlpnMode::RareAlpn,
            v13_mode: V13Mode::NoSupport,
            extension_order: ExtensionOrder::Forward,
        }),
        // Probe 5: TLS 1.2, ALL ciphers, MIDDLE_OUT order, GREASE, RARE_ALPN, NO 1.3, REVERSE extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS12,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::MiddleOut,
            grease: true,
            alpn: AlpnMode::RareAlpn,
            v13_mode: V13Mode::NoSupport,
            extension_order: ExtensionOrder::Reverse,
        }),
        // Probe 6: TLS 1.1, ALL ciphers, FORWARD order, NO_GREASE, ALPN, NO 1.3, FORWARD extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS11,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::Forward,
            grease: false,
            alpn: AlpnMode::Alpn,
            v13_mode: V13Mode::NoSupport,
            extension_order: ExtensionOrder::Forward,
        }),
        // Probe 7: TLS 1.3, ALL ciphers, FORWARD order, NO_GREASE, ALPN, 1.3 support, REVERSE extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS13,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::Forward,
            grease: false,
            alpn: AlpnMode::Alpn,
            v13_mode: V13Mode::Support13,
            extension_order: ExtensionOrder::Reverse,
        }),
        // Probe 8: TLS 1.3, ALL ciphers, REVERSE order, NO_GREASE, ALPN, 1.3 support, FORWARD extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS13,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::Reverse,
            grease: false,
            alpn: AlpnMode::Alpn,
            v13_mode: V13Mode::Support13,
            extension_order: ExtensionOrder::Forward,
        }),
        // Probe 9: TLS 1.3, NO 1.3 ciphers, FORWARD order, NO_GREASE, ALPN, 1.3 support, FORWARD extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS13,
            cipher_list: CipherList::No13,
            cipher_order: CipherOrder::Forward,
            grease: false,
            alpn: AlpnMode::Alpn,
            v13_mode: V13Mode::Support13,
            extension_order: ExtensionOrder::Forward,
        }),
        // Probe 10: TLS 1.3, ALL ciphers, MIDDLE_OUT order, GREASE, ALPN, 1.3 support, REVERSE extensions
        build_probe(JarmProbeOptions {
            hostname: hostname.to_string(),
            port,
            version: TlsVersion::TLS13,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::MiddleOut,
            grease: true,
            alpn: AlpnMode::Alpn,
            v13_mode: V13Mode::Support13,
            extension_order: ExtensionOrder::Reverse,
        }),
    ]
}

/// Build a single JARM probe
fn build_probe(options: JarmProbeOptions) -> JarmProbe {
    let packet = build_client_hello(&options);
    JarmProbe { options, packet }
}

/// Build TLS Client Hello packet
fn build_client_hello(opts: &JarmProbeOptions) -> Vec<u8> {
    let mut payload = vec![0x16]; // Handshake content type
    let mut hello = Vec::new();

    // Record and handshake version
    match opts.version {
        TlsVersion::SSL30 => {
            payload.extend_from_slice(&[0x03, 0x00]);
            hello.extend_from_slice(&[0x03, 0x00]);
        }
        TlsVersion::TLS10 => {
            payload.extend_from_slice(&[0x03, 0x01]);
            hello.extend_from_slice(&[0x03, 0x01]);
        }
        TlsVersion::TLS11 => {
            payload.extend_from_slice(&[0x03, 0x02]);
            hello.extend_from_slice(&[0x03, 0x02]);
        }
        TlsVersion::TLS12 => {
            payload.extend_from_slice(&[0x03, 0x03]);
            hello.extend_from_slice(&[0x03, 0x03]);
        }
        TlsVersion::TLS13 => {
            payload.extend_from_slice(&[0x03, 0x01]); // Record version is 0x0301 for TLS 1.3
            hello.extend_from_slice(&[0x03, 0x03]); // ClientHello version is 0x0303
        }
    }

    // Random (32 bytes)
    let random = random_bytes(32);
    hello.extend_from_slice(&random);

    // Session ID
    let session_id = random_bytes(32);
    hello.push(session_id.len() as u8);
    hello.extend_from_slice(&session_id);

    // Cipher suites
    let ciphers = get_ciphers(opts);
    hello.extend_from_slice(&u16_to_bytes(ciphers.len() as u16));
    hello.extend_from_slice(&ciphers);

    // Compression methods (1 = NULL)
    hello.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let extensions = get_extensions(opts);
    hello.extend_from_slice(&extensions);

    // Build handshake protocol
    let mut handshake = vec![0x01]; // ClientHello type
    handshake.push(0x00); // Length (3 bytes, big-endian)
    handshake.extend_from_slice(&u16_to_bytes(hello.len() as u16));
    handshake.extend_from_slice(&hello);

    // Add length to payload
    payload.extend_from_slice(&u16_to_bytes(handshake.len() as u16));
    payload.extend_from_slice(&handshake);

    payload
}

/// Get cipher suites based on options
fn get_ciphers(opts: &JarmProbeOptions) -> Vec<u8> {
    let mut ciphers: Vec<[u8; 2]> = match opts.cipher_list {
        CipherList::All => vec![
            [0x00, 0x16],
            [0x00, 0x33],
            [0x00, 0x67],
            [0xc0, 0x9e],
            [0xc0, 0xa2],
            [0x00, 0x9e],
            [0x00, 0x39],
            [0x00, 0x6b],
            [0xc0, 0x9f],
            [0xc0, 0xa3],
            [0x00, 0x9f],
            [0x00, 0x45],
            [0x00, 0xbe],
            [0x00, 0x88],
            [0x00, 0xc4],
            [0x00, 0x9a],
            [0xc0, 0x08],
            [0xc0, 0x09],
            [0xc0, 0x23],
            [0xc0, 0xac],
            [0xc0, 0xae],
            [0xc0, 0x2b],
            [0xc0, 0x0a],
            [0xc0, 0x24],
            [0xc0, 0xad],
            [0xc0, 0xaf],
            [0xc0, 0x2c],
            [0xc0, 0x72],
            [0xc0, 0x73],
            [0xcc, 0xa9],
            [0x13, 0x02],
            [0x13, 0x01],
            [0xcc, 0x14],
            [0xc0, 0x07],
            [0xc0, 0x12],
            [0xc0, 0x13],
            [0xc0, 0x27],
            [0xc0, 0x2f],
            [0xc0, 0x14],
            [0xc0, 0x28],
            [0xc0, 0x30],
            [0xc0, 0x60],
            [0xc0, 0x61],
            [0xc0, 0x76],
            [0xc0, 0x77],
            [0xcc, 0xa8],
            [0x13, 0x05],
            [0x13, 0x04],
            [0x13, 0x03],
            [0xcc, 0x13],
            [0xc0, 0x11],
            [0x00, 0x0a],
            [0x00, 0x2f],
            [0x00, 0x3c],
            [0xc0, 0x9c],
            [0xc0, 0xa0],
            [0x00, 0x9c],
            [0x00, 0x35],
            [0x00, 0x3d],
            [0xc0, 0x9d],
            [0xc0, 0xa1],
            [0x00, 0x9d],
            [0x00, 0x41],
            [0x00, 0xba],
            [0x00, 0x84],
            [0x00, 0xc0],
            [0x00, 0x07],
            [0x00, 0x04],
            [0x00, 0x05],
        ],
        CipherList::No13 => vec![
            [0x00, 0x16],
            [0x00, 0x33],
            [0x00, 0x67],
            [0xc0, 0x9e],
            [0xc0, 0xa2],
            [0x00, 0x9e],
            [0x00, 0x39],
            [0x00, 0x6b],
            [0xc0, 0x9f],
            [0xc0, 0xa3],
            [0x00, 0x9f],
            [0x00, 0x45],
            [0x00, 0xbe],
            [0x00, 0x88],
            [0x00, 0xc4],
            [0x00, 0x9a],
            [0xc0, 0x08],
            [0xc0, 0x09],
            [0xc0, 0x23],
            [0xc0, 0xac],
            [0xc0, 0xae],
            [0xc0, 0x2b],
            [0xc0, 0x0a],
            [0xc0, 0x24],
            [0xc0, 0xad],
            [0xc0, 0xaf],
            [0xc0, 0x2c],
            [0xc0, 0x72],
            [0xc0, 0x73],
            [0xcc, 0xa9],
            [0xcc, 0x14],
            [0xc0, 0x07],
            [0xc0, 0x12],
            [0xc0, 0x13],
            [0xc0, 0x27],
            [0xc0, 0x2f],
            [0xc0, 0x14],
            [0xc0, 0x28],
            [0xc0, 0x30],
            [0xc0, 0x60],
            [0xc0, 0x61],
            [0xc0, 0x76],
            [0xc0, 0x77],
            [0xcc, 0xa8],
            [0xcc, 0x13],
            [0xc0, 0x11],
            [0x00, 0x0a],
            [0x00, 0x2f],
            [0x00, 0x3c],
            [0xc0, 0x9c],
            [0xc0, 0xa0],
            [0x00, 0x9c],
            [0x00, 0x35],
            [0x00, 0x3d],
            [0xc0, 0x9d],
            [0xc0, 0xa1],
            [0x00, 0x9d],
            [0x00, 0x41],
            [0x00, 0xba],
            [0x00, 0x84],
            [0x00, 0xc0],
            [0x00, 0x07],
            [0x00, 0x04],
            [0x00, 0x05],
        ],
    };

    // Reorder ciphers
    ciphers = reorder_ciphers(ciphers, opts.cipher_order);

    // Add GREASE if requested
    if opts.grease {
        ciphers.insert(0, random_grease());
    }

    // Flatten to bytes
    let mut result = Vec::new();
    for cipher in ciphers {
        result.extend_from_slice(&cipher);
    }

    result
}

/// Reorder cipher list
fn reorder_ciphers(mut ciphers: Vec<[u8; 2]>, order: CipherOrder) -> Vec<[u8; 2]> {
    match order {
        CipherOrder::Forward => ciphers,
        CipherOrder::Reverse => {
            ciphers.reverse();
            ciphers
        }
        CipherOrder::TopHalf => {
            let len = ciphers.len();
            if len % 2 == 1 {
                let mid = len / 2;
                let mut result = vec![ciphers[mid]];
                let reversed: Vec<_> = ciphers.into_iter().rev().collect();
                result.extend_from_slice(&reversed[0..(len / 2)]);
                result
            } else {
                let reversed: Vec<_> = ciphers.into_iter().rev().collect();
                reversed[0..(len / 2)].to_vec()
            }
        }
        CipherOrder::BottomHalf => {
            let len = ciphers.len();
            if len % 2 == 1 {
                ciphers[(len / 2) + 1..].to_vec()
            } else {
                ciphers[len / 2..].to_vec()
            }
        }
        CipherOrder::MiddleOut => {
            let len = ciphers.len();
            let middle = len / 2;
            let mut result = Vec::new();

            if len % 2 == 1 {
                result.push(ciphers[middle]);
                for i in 1..=middle {
                    result.push(ciphers[middle + i]);
                    result.push(ciphers[middle - i]);
                }
            } else {
                // Reverse left half, keep right half in order
                for cipher in ciphers.iter().take(middle).rev() {
                    result.push(*cipher);
                }
                for cipher in ciphers.iter().skip(middle).take(len - middle) {
                    result.push(*cipher);
                }
            }

            result
        }
    }
}

/// Get extensions
fn get_extensions(opts: &JarmProbeOptions) -> Vec<u8> {
    let mut all_extensions = Vec::new();

    // GREASE extension
    if opts.grease {
        all_extensions.extend_from_slice(&random_grease());
        all_extensions.extend_from_slice(&[0x00, 0x00]);
    }

    // Server Name Indication (SNI)
    all_extensions.extend_from_slice(&ext_server_name(&opts.hostname));

    // Extended Master Secret
    all_extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    // SessionTicket TLS
    all_extensions.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x01]);

    // Renegotiation Info
    all_extensions.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

    // Supported Groups
    all_extensions.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
    ]);

    // EC Point Formats
    all_extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

    // Session Ticket
    all_extensions.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

    // ALPN
    if opts.alpn != AlpnMode::NoSupport {
        all_extensions.extend_from_slice(&ext_alpn(opts));
    }

    // Signature Algorithms
    all_extensions.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08,
        0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
    ]);

    // Key Share
    all_extensions.extend_from_slice(&ext_key_share(opts.grease));

    // PSK Key Exchange Modes
    all_extensions.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);

    // Supported Versions
    if opts.version == TlsVersion::TLS13 || opts.v13_mode == V13Mode::Support12Only {
        all_extensions.extend_from_slice(&ext_supported_versions(opts));
    }

    // Wrap extensions with length
    let mut result = u16_to_bytes(all_extensions.len() as u16).to_vec();
    result.extend_from_slice(&all_extensions);

    result
}

/// Server Name Indication extension
fn ext_server_name(name: &str) -> Vec<u8> {
    let mut ext = vec![0x00, 0x00]; // Extension type

    let mut list = Vec::new();
    list.push(0x00); // Name type: hostname
    list.extend_from_slice(&u16_to_bytes(name.len() as u16));
    list.extend_from_slice(name.as_bytes());

    let mut data = Vec::new();
    data.extend_from_slice(&u16_to_bytes(list.len() as u16));
    data.extend_from_slice(&list);

    ext.extend_from_slice(&u16_to_bytes(data.len() as u16));
    ext.extend_from_slice(&data);

    ext
}

/// ALPN extension
fn ext_alpn(opts: &JarmProbeOptions) -> Vec<u8> {
    let mut ext = vec![0x00, 0x10]; // Extension type

    let alpn_list: Vec<&[u8]> = match opts.alpn {
        AlpnMode::RareAlpn => vec![
            b"\x08http/0.9",
            b"\x08http/1.0",
            b"\x06spdy/1",
            b"\x06spdy/2",
            b"\x06spdy/3",
            b"\x03h2c",
            b"\x02hq",
        ],
        AlpnMode::Alpn => vec![
            b"\x08http/0.9",
            b"\x08http/1.0",
            b"\x08http/1.1",
            b"\x06spdy/1",
            b"\x06spdy/2",
            b"\x06spdy/3",
            b"\x02h2",
            b"\x03h2c",
            b"\x02hq",
        ],
        AlpnMode::NoSupport => return Vec::new(),
    };

    // Reorder ALPN if requested
    let mut ordered_list = alpn_list;
    if opts.extension_order == ExtensionOrder::Reverse {
        ordered_list.reverse();
    }

    let mut all_alpn = Vec::new();
    for alpn in ordered_list {
        all_alpn.extend_from_slice(alpn);
    }

    ext.extend_from_slice(&u16_to_bytes((all_alpn.len() + 2) as u16));
    ext.extend_from_slice(&u16_to_bytes(all_alpn.len() as u16));
    ext.extend_from_slice(&all_alpn);

    ext
}

/// Key Share extension
fn ext_key_share(grease: bool) -> Vec<u8> {
    let mut ext = vec![0x00, 0x33]; // Extension type
    let mut share_ext = Vec::new();

    if grease {
        share_ext.extend_from_slice(&random_grease());
        share_ext.extend_from_slice(&[0x00, 0x01, 0x00]);
    }

    // x25519 key share
    share_ext.extend_from_slice(&[0x00, 0x1d]); // Group: x25519
    share_ext.extend_from_slice(&[0x00, 0x20]); // Length: 32
    share_ext.extend_from_slice(&random_bytes(32));

    let first_length = share_ext.len() + 2;
    let second_length = share_ext.len();

    ext.extend_from_slice(&u16_to_bytes(first_length as u16));
    ext.extend_from_slice(&u16_to_bytes(second_length as u16));
    ext.extend_from_slice(&share_ext);

    ext
}

/// Supported Versions extension
fn ext_supported_versions(opts: &JarmProbeOptions) -> Vec<u8> {
    let mut ext = vec![0x00, 0x2b]; // Extension type

    let mut versions: Vec<[u8; 2]> = match opts.v13_mode {
        V13Mode::Support12Only => vec![[0x03, 0x01], [0x03, 0x02], [0x03, 0x03]],
        V13Mode::Support13 => vec![[0x03, 0x01], [0x03, 0x02], [0x03, 0x03], [0x03, 0x04]],
        V13Mode::NoSupport => vec![[0x03, 0x01], [0x03, 0x02], [0x03, 0x03]],
    };

    if opts.extension_order == ExtensionOrder::Reverse {
        versions.reverse();
    }

    let mut ver = Vec::new();
    if opts.grease {
        ver.extend_from_slice(&random_grease());
    }

    for v in versions {
        ver.extend_from_slice(&v);
    }

    ext.extend_from_slice(&u16_to_bytes((ver.len() + 1) as u16));
    ext.push(ver.len() as u8);
    ext.extend_from_slice(&ver);

    ext
}

/// Generate random bytes
fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Generate random GREASE value
fn random_grease() -> [u8; 2] {
    let mut rng = rand::thread_rng();
    let val = rng.gen_range(0..16);
    let byte = 0x0a + (val << 4);
    [byte, byte]
}

/// Convert u16 to big-endian bytes
fn u16_to_bytes(val: u16) -> [u8; 2] {
    val.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_probes() {
        let probes = get_probes("example.com", 443);
        assert_eq!(probes.len(), 10);

        // Verify probe 1
        assert_eq!(probes[0].options.version, TlsVersion::TLS12);
        assert_eq!(probes[0].options.cipher_order, CipherOrder::Forward);
        assert!(!probes[0].options.grease);

        // Verify probe 10
        assert_eq!(probes[9].options.version, TlsVersion::TLS13);
        assert_eq!(probes[9].options.cipher_order, CipherOrder::MiddleOut);
        assert!(probes[9].options.grease);
    }

    #[test]
    fn test_cipher_reordering() {
        let ciphers = vec![[0x01, 0x02], [0x03, 0x04], [0x05, 0x06], [0x07, 0x08]];

        // Forward
        let forward = reorder_ciphers(ciphers.clone(), CipherOrder::Forward);
        assert_eq!(forward, ciphers);

        // Reverse
        let reverse = reorder_ciphers(ciphers.clone(), CipherOrder::Reverse);
        assert_eq!(
            reverse,
            vec![[0x07, 0x08], [0x05, 0x06], [0x03, 0x04], [0x01, 0x02]]
        );

        // Middle Out
        let middle_out = reorder_ciphers(ciphers.clone(), CipherOrder::MiddleOut);
        assert_eq!(
            middle_out,
            vec![[0x03, 0x04], [0x01, 0x02], [0x05, 0x06], [0x07, 0x08]]
        );
    }

    #[test]
    fn test_client_hello_structure() {
        let opts = JarmProbeOptions {
            hostname: "example.com".to_string(),
            port: 443,
            version: TlsVersion::TLS12,
            cipher_list: CipherList::All,
            cipher_order: CipherOrder::Forward,
            grease: false,
            alpn: AlpnMode::Alpn,
            v13_mode: V13Mode::Support12Only,
            extension_order: ExtensionOrder::Forward,
        };

        let packet = build_client_hello(&opts);

        // Should start with handshake content type (0x16)
        assert_eq!(packet[0], 0x16);

        // Version should be 0x0303 for TLS 1.2
        assert_eq!(packet[1], 0x03);
        assert_eq!(packet[2], 0x03);

        // Should have reasonable length (> 100 bytes)
        assert!(packet.len() > 100);
    }
}
