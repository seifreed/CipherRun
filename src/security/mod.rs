/*
 * Copyright (C) 2026 Marc Rivero López
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//! Security Module
//!
//! Provides security-related functionality including input validation,
//! sanitization, and protection against common vulnerabilities.

pub mod input_validation;

pub use input_validation::{
    ValidationError, is_private_ip, sanitize_path, validate_cipher, validate_hostname,
    validate_port, validate_starttls_protocol, validate_target,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_port_reexport() {
        assert!(validate_port(443).is_ok());
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_hostname_reexport() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("bad host").is_err());
    }

    #[test]
    fn test_validate_cipher_reexport() {
        assert!(validate_cipher("HIGH:!aNULL").is_ok());
        assert!(validate_cipher("bad;cipher").is_err());
    }

    #[test]
    fn test_validate_starttls_protocol_reexport() {
        assert!(validate_starttls_protocol("smtp").is_ok());
        assert!(validate_starttls_protocol("badproto").is_err());
    }
}
