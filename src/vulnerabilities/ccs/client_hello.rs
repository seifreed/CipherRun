use crate::Result;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;

pub(super) fn minimal_tls10_rsa() -> Result<Vec<u8>> {
    let mut builder = ClientHelloBuilder::new(Protocol::TLS10);
    builder.for_rsa_key_exchange();
    builder.build_minimal()
}
