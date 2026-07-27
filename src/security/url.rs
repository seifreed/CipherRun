pub(crate) fn raw_url_host(url: &str) -> Option<&str> {
    let authority = url.split_once("://")?.1;
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);

    if let Some(host) = host.strip_prefix('[') {
        host.split_once(']').map(|(host, _)| host)
    } else {
        Some(host.split_once(':').map_or(host, |(hostname, _)| hostname))
    }
}
