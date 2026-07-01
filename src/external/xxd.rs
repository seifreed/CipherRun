// Hex dump utilities for rendering exported TLS handshake bytes.

/// Simple hex dump implementation (xxd-style offset/hex/ASCII layout)
pub fn simple_hex_dump(data: &[u8], cols: usize) -> String {
    let cols = cols.max(1);
    let mut output = String::new();

    for (i, chunk) in data.chunks(cols).enumerate() {
        // Offset
        output.push_str(&format!("{:08x}: ", i * cols));

        // Hex values
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x}", byte));
            if j % 2 == 1 {
                output.push(' ');
            }
        }

        // Pad the hex section so the ASCII column aligns with full rows. A row of
        // `n` bytes occupies `n*2 + n/2` columns (2 hex chars per byte plus a space
        // after every odd index); the integer divisions do not distribute, so the
        // width must be computed from the full and partial totals, not factored.
        let n = chunk.len();
        let padding = (cols * 2 + cols / 2) - (n * 2 + n / 2);
        for _ in 0..padding {
            output.push(' ');
        }

        output.push(' ');

        // ASCII representation
        for byte in chunk {
            if *byte >= 32 && *byte <= 126 {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }

        output.push('\n');
    }

    output
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8], uppercase: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if uppercase {
                format!("{:02X}", b)
            } else {
                format!("{:02x}", b)
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_hex_dump() {
        let data = b"Hello, World!";
        let dump = simple_hex_dump(data, 16);
        assert!(dump.contains("4865")); // "He" in hex
        assert!(dump.contains("6c6c")); // "ll" in hex
        assert!(dump.contains("Hello")); // ASCII representation
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = b"Hello";
        let hex_lower = bytes_to_hex(bytes, false);
        assert_eq!(hex_lower, "48656c6c6f");

        let hex_upper = bytes_to_hex(bytes, true);
        assert_eq!(hex_upper, "48656C6C6F");
    }

    #[test]
    fn test_bytes_to_hex_empty() {
        let hex = bytes_to_hex(&[], false);
        assert_eq!(hex, "");
    }

    #[test]
    fn test_simple_hex_dump_ascii_column_aligns_for_partial_row() {
        // A full 16-byte row and an odd-length partial row must place the ASCII
        // section at the same column. Odd partial rows previously padded one space
        // short due to non-distributing integer division.
        let cols = 16;
        let full = simple_hex_dump(&[0x41u8; 16], cols);
        let partial = simple_hex_dump(&[0x41u8], cols);

        // Hex bytes render lowercase ("41"), so the first uppercase 'A' marks the
        // start of the ASCII section.
        let ascii_col = |line: &str| line.find('A').expect("printable byte present");
        let full_line = full.lines().next().expect("one row");
        let partial_line = partial.lines().next().expect("one row");

        assert_eq!(
            ascii_col(full_line),
            ascii_col(partial_line),
            "ASCII column must align between full and partial rows"
        );
    }

    #[test]
    fn test_simple_hex_dump_zero_columns_does_not_panic() {
        let dump = simple_hex_dump(b"AB", 0);

        assert!(dump.contains("41 A"));
        assert!(dump.contains("42 B"));
    }
}
