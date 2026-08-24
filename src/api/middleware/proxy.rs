use crate::api::{server::PeerAddr, state::AppState};
use axum::{extract::ConnectInfo, http::Request};
use std::net::IpAddr;
use std::sync::Arc;

/// Resolve the client address without trusting spoofable forwarding headers.
pub fn client_ip<B>(request: &Request<B>, state: &Arc<AppState>) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<PeerAddr>>()
        .map(|ConnectInfo(PeerAddr(address))| address.ip());
    let Some(peer) = peer else {
        return None;
    };
    if !state
        .config
        .trusted_proxy_cidrs
        .iter()
        .any(|cidr| cidr.contains(peer))
    {
        return Some(peer);
    }
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
        .or(Some(peer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiConfig;
    use axum::http::Request;
    use std::net::SocketAddr;

    #[test]
    fn ignores_forwarded_address_from_untrusted_peer() {
        let state = Arc::new(AppState::new(ApiConfig::default()).unwrap());
        let request = Request::builder()
            .header("x-forwarded-for", "198.51.100.8")
            .body(())
            .unwrap();
        let mut request = request;
        request
            .extensions_mut()
            .insert(ConnectInfo(PeerAddr("192.0.2.10:443".parse().unwrap())));
        assert_eq!(
            client_ip(&request, &state),
            Some("192.0.2.10".parse().unwrap())
        );
    }

    #[test]
    fn accepts_forwarded_address_from_trusted_proxy() {
        let mut config = ApiConfig::default();
        config.trusted_proxy_cidrs = vec!["192.0.2.0/24".parse().unwrap()];
        let state = Arc::new(AppState::new(config).unwrap());
        let mut request = Request::builder()
            .header("x-forwarded-for", "198.51.100.8, 192.0.2.10")
            .body(())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(PeerAddr(SocketAddr::new(
                "192.0.2.10".parse().unwrap(),
                443,
            ))));
        assert_eq!(
            client_ip(&request, &state),
            Some("198.51.100.8".parse().unwrap())
        );
    }
}
