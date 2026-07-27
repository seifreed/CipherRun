use super::network::Target;
use std::net::IpAddr;

pub(crate) fn example_target() -> Target {
    Target::with_ips(
        "example.test".to_string(),
        443,
        vec!["127.0.0.1".parse().expect("valid IP")],
    )
    .expect("test assertion should succeed")
}

pub(crate) fn localhost_target(port: u16) -> Target {
    Target::with_ips(
        "localhost".to_string(),
        port,
        vec![IpAddr::from([127, 0, 0, 1])],
    )
    .unwrap()
}
