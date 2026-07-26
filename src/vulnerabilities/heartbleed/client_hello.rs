use crate::Result;
use crate::protocols::handshake::ClientHelloBuilder;
use crate::protocols::{Extension, Protocol};

pub(super) fn with_heartbeat_extension(
    protocol: Protocol,
    target_hostname: &str,
    sni_hostname: Option<&str>,
) -> Result<Vec<u8>> {
    let mut builder = ClientHelloBuilder::new(protocol);
    builder.add_ciphers(&[0xc014, 0xc00a, 0x0039, 0x0038, 0x0035]);
    builder.add_extension(Extension::new(0x000f, vec![0x01]));

    let sni = crate::utils::network::sni_hostname_for_target(target_hostname, sni_hostname);
    builder.build_with_defaults(sni.as_deref())
}
