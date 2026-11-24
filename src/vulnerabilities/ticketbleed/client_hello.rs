use crate::Result;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;

/// Distinctive 16-byte Session ID sent in the resumption ClientHello.
///
/// A Ticketbleed-vulnerable F5 BIG-IP echoes a full 32-byte Session ID in its
/// ServerHello, beginning with this marker and padding the remainder with
/// uninitialized memory.
pub(super) const SESSION_ID_MARKER: [u8; 16] = [
    0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

pub(super) fn with_empty_session_ticket() -> Result<Vec<u8>> {
    let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
    builder.for_vulnerability_testing().add_session_ticket();
    builder.build()
}

pub(super) fn with_received_ticket(
    server_response: &[u8],
    extract_ticket: impl FnOnce(&[u8]) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<u8>> {
    let ticket = extract_ticket(server_response)?;

    let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
    builder.for_vulnerability_testing();

    if let Some(ticket_data) = ticket {
        builder.add_session_ticket_with_data(&ticket_data);
        builder.set_session_id(&SESSION_ID_MARKER);
    } else {
        builder.add_session_ticket();
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::{SESSION_ID_MARKER, with_empty_session_ticket, with_received_ticket};

    #[test]
    fn empty_session_ticket_client_hello_contains_ticket_extension() {
        let hello = with_empty_session_ticket().expect("ClientHello should build");

        assert!(hello.windows(2).any(|window| window == [0x00, 0x23]));
    }

    #[test]
    fn received_ticket_is_reused_with_marker_session_id() {
        let ticket = [0x12, 0x34, 0x56];
        let hello = with_received_ticket(b"server response", |_| Ok(Some(ticket.to_vec())))
            .expect("ClientHello should build");

        assert!(
            hello
                .windows(SESSION_ID_MARKER.len())
                .any(|w| w == SESSION_ID_MARKER)
        );
        assert!(hello.windows(ticket.len()).any(|w| w == ticket));
    }

    #[test]
    fn missing_ticket_uses_empty_ticket_extension() {
        let hello = with_received_ticket(b"server response", |_| Ok(None))
            .expect("ClientHello should build");

        assert!(
            !hello
                .windows(SESSION_ID_MARKER.len())
                .any(|w| w == SESSION_ID_MARKER)
        );
        assert!(hello.windows(2).any(|w| w == [0x00, 0x23]));
    }

    #[test]
    fn ticket_extraction_error_is_propagated() {
        let error = with_received_ticket(b"server response", |_| {
            Err(crate::TlsError::ParseError {
                message: "malformed ticket".to_string(),
            })
        })
        .expect_err("ticket extraction errors must be returned");

        assert!(error.to_string().contains("malformed ticket"));
    }

    #[test]
    fn oversized_received_ticket_build_error_is_propagated() {
        let ticket = vec![0; u16::MAX as usize + 1];
        let result = with_received_ticket(b"server response", |_| Ok(Some(ticket)));

        assert!(result.is_err(), "oversized ticket data must be rejected");
    }
}
