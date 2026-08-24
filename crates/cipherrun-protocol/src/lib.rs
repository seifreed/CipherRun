//! Dependency-light TLS protocol contracts shared by CipherRun consumers.

mod model;

pub use model::{Protocol, ProtocolTestResult};

#[cfg(test)]
mod tests {
    use super::Protocol;
    use std::str::FromStr;

    #[test]
    fn protocol_round_trips_and_normalizes_input() {
        assert_eq!(Protocol::from_str(" tls-1.2 ").unwrap(), Protocol::TLS12);
        assert_eq!(Protocol::TLS13.to_string(), "TLS 1.3");
        assert_eq!(Protocol::TLS13.as_hex(), 0x0304);
    }

    #[test]
    fn protocol_all_excludes_quic() {
        assert!(!Protocol::all().contains(&Protocol::QUIC));
    }
}
