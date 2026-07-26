pub mod api;
pub mod mock_scanner;
pub mod sqlite;

pub async fn create_target(host: &str, port: u16) -> cipherrun::utils::network::Target {
    let target = format!("{host}:{port}");
    cipherrun::utils::network::Target::parse(&target)
        .await
        .expect("Failed to parse target")
}
