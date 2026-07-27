pub(crate) fn example_target() -> crate::utils::network::Target {
    crate::utils::network::Target::with_ips(
        "example.com".to_string(),
        443,
        vec!["93.184.216.34".parse().unwrap()],
    )
    .unwrap()
}
