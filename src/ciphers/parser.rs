// Cipher Parser - Formats and displays cipher information

use super::{CipherStrength, CipherSuite, tester::ProtocolCipherSummary};
use crate::protocols::Protocol;
use colored::*;
use std::fmt;

/// Format cipher suite for display
pub struct CipherFormatter;

impl CipherFormatter {
    /// Format cipher name with color based on strength
    pub fn format_cipher(cipher: &CipherSuite, colorize: bool) -> String {
        let name = &cipher.openssl_name;

        if !colorize {
            return name.to_string();
        }

        match cipher.strength() {
            CipherStrength::NULL => name.red().bold().to_string(),
            CipherStrength::Export => name.red().to_string(),
            CipherStrength::Low => name.yellow().to_string(),
            CipherStrength::Medium => name.normal().to_string(),
            CipherStrength::High => name.green().to_string(),
        }
    }

    /// Format cipher with details
    pub fn format_cipher_detailed(cipher: &CipherSuite, colorize: bool) -> String {
        let name = Self::format_cipher(cipher, colorize);
        let mut details = Vec::new();

        // Key exchange
        if !cipher.key_exchange.is_empty() {
            details.push(format!("Kx={}", cipher.key_exchange));
        }

        // Authentication
        if !cipher.authentication.is_empty() {
            details.push(format!("Au={}", cipher.authentication));
        }

        // Encryption
        if !cipher.encryption.is_empty() {
            details.push(format!("Enc={}", cipher.encryption));
        }

        // MAC
        if !cipher.mac.is_empty() && cipher.mac != "AEAD" {
            details.push(format!("Mac={}", cipher.mac));
        }

        // Bits
        details.push(format!("{}bits", cipher.bits));

        // Forward Secrecy
        if cipher.has_forward_secrecy() {
            let fs = if colorize {
                "FS".green().to_string()
            } else {
                "FS".to_string()
            };
            details.push(fs);
        }

        // AEAD
        if cipher.is_aead() {
            let aead = if colorize {
                "AEAD".green().to_string()
            } else {
                "AEAD".to_string()
            };
            details.push(aead);
        }

        format!("{} ({})", name, details.join(", "))
    }

    /// Format cipher hexcode
    pub fn format_hexcode(cipher: &CipherSuite) -> String {
        format!("0x{}", cipher.hexcode.to_uppercase())
    }

    /// Format strength indicator
    pub fn format_strength(strength: CipherStrength, colorize: bool) -> String {
        let text = strength.to_string();

        if !colorize {
            return text;
        }

        match strength {
            CipherStrength::NULL => text.red().bold().to_string(),
            CipherStrength::Export => text.red().to_string(),
            CipherStrength::Low => text.yellow().to_string(),
            CipherStrength::Medium => text.normal().to_string(),
            CipherStrength::High => text.green().to_string(),
        }
    }
}

/// Display summary of cipher testing results
impl fmt::Display for ProtocolCipherSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Protocol: {}", self.protocol)?;
        writeln!(f, "Supported Ciphers: {}", self.counts.total)?;
        writeln!(f)?;

        // Cipher counts by strength
        if self.counts.null_ciphers > 0 {
            writeln!(f, "  NULL ciphers:   {}", self.counts.null_ciphers)?;
        }
        if self.counts.export_ciphers > 0 {
            writeln!(f, "  EXPORT ciphers: {}", self.counts.export_ciphers)?;
        }
        if self.counts.low_strength > 0 {
            writeln!(f, "  LOW strength:   {}", self.counts.low_strength)?;
        }
        if self.counts.medium_strength > 0 {
            writeln!(f, "  MEDIUM strength: {}", self.counts.medium_strength)?;
        }
        if self.counts.high_strength > 0 {
            writeln!(f, "  HIGH strength:  {}", self.counts.high_strength)?;
        }

        writeln!(f)?;

        // Features
        writeln!(
            f,
            "  Forward Secrecy: {}/{}",
            self.counts.forward_secrecy, self.counts.total
        )?;
        writeln!(
            f,
            "  AEAD:            {}/{}",
            self.counts.aead, self.counts.total
        )?;

        writeln!(f)?;

        // Server preference
        if self.server_ordered {
            writeln!(f, "  Server Cipher Order: YES")?;
            if let Some(cipher) = &self.preferred_cipher {
                writeln!(f, "  Preferred Cipher: {}", cipher.openssl_name)?;
            }
        } else {
            writeln!(f, "  Server Cipher Order: NO (client preference)")?;
        }

        Ok(())
    }
}

/// Create cipher list output in testssl.sh style
pub struct CipherListFormatter;

impl CipherListFormatter {
    /// Format cipher list for terminal output
    pub fn format_list(ciphers: &[CipherSuite], protocol: Protocol, colorize: bool) -> String {
        let mut output = String::new();

        if colorize {
            output.push_str(&format!("\n{}\n", protocol.to_string().cyan().bold()));
        } else {
            output.push_str(&format!("\n{}\n", protocol));
        }

        output.push_str(&"-".repeat(80));
        output.push('\n');

        for cipher in ciphers {
            let hex = CipherFormatter::format_hexcode(cipher);
            let name = CipherFormatter::format_cipher(cipher, colorize);
            let strength = CipherFormatter::format_strength(cipher.strength(), colorize);

            // Format: hexcode  name  [strength]  details
            output.push_str(&format!("{:<12} {:<45} [{:<8}]", hex, name, strength));

            // Add markers
            let mut markers = Vec::new();
            if cipher.has_forward_secrecy() {
                markers.push("FS");
            }
            if cipher.is_aead() {
                markers.push("AEAD");
            }
            if cipher.export {
                markers.push("EXPORT");
            }

            if !markers.is_empty() {
                output.push_str(&format!(" {}", markers.join(", ")));
            }

            output.push('\n');
        }

        output
    }

    /// Format cipher list as CSV
    pub fn format_csv(ciphers: &[CipherSuite], protocol: Protocol) -> String {
        let mut output = String::new();

        // Header
        output.push_str(
            "Protocol,Hexcode,OpenSSL Name,IANA Name,Kx,Au,Enc,Mac,Bits,FS,AEAD,Export,Strength\n",
        );

        // Data rows
        for cipher in ciphers {
            output.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                protocol,
                cipher.hexcode,
                cipher.openssl_name,
                cipher.iana_name,
                cipher.key_exchange,
                cipher.authentication,
                cipher.encryption,
                cipher.mac,
                cipher.bits,
                cipher.has_forward_secrecy(),
                cipher.is_aead(),
                cipher.export,
                cipher.strength()
            ));
        }

        output
    }

    /// Format cipher list as JSON
    pub fn format_json(
        summary: &ProtocolCipherSummary,
        pretty: bool,
    ) -> Result<String, serde_json::Error> {
        if pretty {
            serde_json::to_string_pretty(summary)
        } else {
            serde_json::to_string(summary)
        }
    }
}

/// Create cipher comparison table
pub struct CipherComparisonFormatter;

impl CipherComparisonFormatter {
    /// Compare ciphers across protocols
    pub fn format_comparison(
        summaries: &std::collections::HashMap<Protocol, ProtocolCipherSummary>,
        colorize: bool,
    ) -> String {
        let mut output = String::new();

        if colorize {
            output.push_str(&format!(
                "\n{}\n",
                "Cipher Support Across Protocols".cyan().bold()
            ));
        } else {
            output.push_str("\nCipher Support Across Protocols\n");
        }

        output.push_str(&"=".repeat(80));
        output.push('\n');

        // Header
        output.push_str(&format!(
            "{:<10} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
            "Protocol", "Total", "NULL", "EXPORT", "FS", "AEAD"
        ));
        output.push_str(&"-".repeat(80));
        output.push('\n');

        // Sort protocols
        let mut protocols: Vec<_> = summaries.keys().collect();
        protocols.sort_by_key(|p| match p {
            Protocol::SSLv2 => 0,
            Protocol::SSLv3 => 1,
            Protocol::TLS10 => 2,
            Protocol::TLS11 => 3,
            Protocol::TLS12 => 4,
            Protocol::TLS13 => 5,
            Protocol::QUIC => 6,
        });

        for protocol in protocols {
            if let Some(summary) = summaries.get(protocol) {
                let proto_str = if colorize {
                    protocol.to_string().cyan().to_string()
                } else {
                    protocol.to_string()
                };

                output.push_str(&format!(
                    "{:<10} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
                    proto_str,
                    summary.counts.total,
                    summary.counts.null_ciphers,
                    summary.counts.export_ciphers,
                    summary.counts.forward_secrecy,
                    summary.counts.aead
                ));
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_formatting() {
        let cipher = CipherSuite {
            hexcode: "c030".to_string(),
            openssl_name: "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            iana_name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES256-GCM".to_string(),
            mac: "SHA384".to_string(),
            bits: 256,
            export: false,
        };

        let formatted = CipherFormatter::format_cipher(&cipher, false);
        assert_eq!(formatted, "ECDHE-RSA-AES256-GCM-SHA384");

        let hex = CipherFormatter::format_hexcode(&cipher);
        assert_eq!(hex, "0xC030");

        let detailed = CipherFormatter::format_cipher_detailed(&cipher, false);
        assert!(detailed.contains("ECDHE"));
        assert!(detailed.contains("256bits"));
        assert!(detailed.contains("FS"));
        assert!(detailed.contains("AEAD"));
    }

    #[test]
    fn test_strength_formatting() {
        let high = CipherFormatter::format_strength(CipherStrength::High, false);
        assert_eq!(high, "HIGH");

        let null = CipherFormatter::format_strength(CipherStrength::NULL, false);
        assert_eq!(null, "NULL");
    }

    #[test]
    fn test_csv_format() {
        let cipher = CipherSuite {
            hexcode: "c030".to_string(),
            openssl_name: "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            iana_name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            protocol: "TLSv1.2".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES256-GCM".to_string(),
            mac: "SHA384".to_string(),
            bits: 256,
            export: false,
        };

        let csv = CipherListFormatter::format_csv(&[cipher], Protocol::TLS12);
        assert!(csv.contains("Protocol,Hexcode"));
        assert!(csv.contains("TLS 1.2,c030"));
        assert!(csv.contains("ECDHE-RSA-AES256-GCM-SHA384"));
    }
}
