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
