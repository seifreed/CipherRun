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
