use crate::Result;
use crate::protocols::Protocol;
use crate::protocols::handshake::ClientHelloBuilder;

pub(super) fn single_cipher(
    protocol: Protocol,
    hexcode: u16,
    sni_hostname: Option<&str>,
) -> Result<Vec<u8>> {
    let mut builder = ClientHelloBuilder::new(protocol);
    builder.add_cipher(hexcode);
    builder.build_with_defaults(sni_hostname)
}
