use super::network::Target;

pub(crate) fn example_target() -> Target {
    Target::with_ips(
        "example.test".to_string(),
        443,
        vec!["127.0.0.1".parse().expect("valid IP")],
    )
    .expect("test assertion should succeed")
}
