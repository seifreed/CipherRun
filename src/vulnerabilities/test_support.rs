use crate::utils::network::Target;
use std::net::IpAddr;

pub(crate) fn two_ip_localhost_target(port: u16) -> Target {
    target_with_ips(
        "localhost",
        port,
        [IpAddr::from([127, 0, 0, 2]), IpAddr::from([127, 0, 0, 1])],
    )
}

pub(crate) fn two_ip_example_target(port: u16) -> Target {
    target_with_ips(
        "example.com",
        port,
        [IpAddr::from([192, 0, 2, 1]), IpAddr::from([192, 0, 2, 2])],
    )
}

fn target_with_ips(hostname: &str, port: u16, ips: [IpAddr; 2]) -> Target {
    Target::with_ips(hostname.to_string(), port, ips.to_vec()).unwrap()
}

pub(crate) async fn spawn_dummy_server(max_accepts: usize) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test server should bind");
    let addr = listener.local_addr().expect("test server should have addr");
    tokio::spawn(async move {
        for _ in 0..max_accepts {
            if let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        }
    });
    addr
}

pub(crate) fn write_u16_at(data: &mut [u8], offset: usize, value: u16) {
    data.get_mut(offset..offset + 2)
        .expect("test fixture should contain u16 placeholder")
        .copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u24_at(data: &mut [u8], offset: usize, value: usize) {
    data.get_mut(offset..offset + 3)
        .expect("test fixture should contain u24 placeholder")
        .copy_from_slice(&[
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]);
}
