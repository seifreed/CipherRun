use cipherrun::utils::network::Target;
use cipherrun::vulnerabilities::ticketbleed::TicketbleedTester;
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn public_probe_sends_empty_ticket_client_hello_from_library_build() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener should bind");
    let port = listener.local_addr().expect("listener address").port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("probe should connect");
        let mut client_hello = vec![0; 4096];
        let length = socket
            .read(&mut client_hello)
            .await
            .expect("probe ClientHello should arrive");
        client_hello.truncate(length);
        let mut ticket_response = vec![0x16, 0x03, 0x03, 0x00, 0x0d, 0x04, 0x00, 0x00, 0x09];
        ticket_response.extend_from_slice(&[0, 0, 0, 0, 0, 3, 0x12, 0x34, 0x56]);
        socket
            .write_all(&ticket_response)
            .await
            .expect("test session ticket should send");
        let mut resumed_client_hello = vec![0; 4096];
        let length = socket
            .read(&mut resumed_client_hello)
            .await
            .expect("resumed ClientHello should arrive");
        resumed_client_hello.truncate(length);
        (client_hello, resumed_client_hello)
    });

    let target = Target::with_ips(
        "example.com".to_string(),
        port,
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    )
    .expect("loopback target should be valid");
    let result = TicketbleedTester::new(target)
        .test()
        .await
        .expect("probe should report an inconclusive result after peer closes");
    let (client_hello, resumed_client_hello) =
        server.await.expect("test server task should complete");

    assert!(client_hello.starts_with(&[0x16, 0x03]));
    assert!(client_hello.windows(2).any(|window| window == [0x00, 0x23]));
    assert!(
        resumed_client_hello
            .windows(3)
            .any(|window| window == [0x12, 0x34, 0x56])
    );
    assert!(result.inconclusive);
    assert!(!result.vulnerable);
}
