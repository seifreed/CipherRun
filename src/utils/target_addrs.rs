use std::net::SocketAddr;

use crate::utils::network::Target;
use crate::{Result, TlsError};

pub(crate) fn socket_addrs_for_probe(
    target: &Target,
    test_all_ips: bool,
) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = if test_all_ips {
        target.socket_addrs()
    } else {
        target.socket_addrs().first().copied().into_iter().collect()
    };
    if addrs.is_empty() {
        Err(TlsError::NoSocketAddresses)
    } else {
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_first_or_all_socket_addrs() {
        let target = Target::with_ips(
            "example.com".to_string(),
            443,
            vec!["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()],
        )
        .unwrap();

        assert_eq!(socket_addrs_for_probe(&target, false).unwrap().len(), 1);
        assert_eq!(socket_addrs_for_probe(&target, true).unwrap().len(), 2);
    }
}
