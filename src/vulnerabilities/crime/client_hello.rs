use crate::Result;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;

pub(super) fn with_compression() -> Result<Vec<u8>> {
    let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
    builder.for_rsa_key_exchange().with_compression(true);
    builder.build()
}

pub(super) fn with_npn() -> Result<Vec<u8>> {
    let mut builder = ClientHelloBuilder::new(Protocol::TLS12);
    builder
        .for_rsa_key_exchange()
        .with_compression(true)
        .add_npn();
    builder.build()
}
