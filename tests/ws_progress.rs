// WebSocket progress streaming tests (no mocks).

use axum::{
    Router,
    extract::{Path, State, WebSocketUpgrade},
    response::Response,
    routing::get,
};
use cipherrun::api::models::response::ProgressMessage;
use cipherrun::api::ws::progress::{WsState, handle_scan_websocket, handle_websocket};
use futures::StreamExt;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, oneshot};
use tokio::time::{Duration, timeout};
use tokio_tungstenite::connect_async;

async fn start_ws_server() -> (
    String,
    broadcast::Sender<ProgressMessage>,
    oneshot::Sender<()>,
) {
    let (tx, _rx) = broadcast::channel(16);
    let state = Arc::new(WsState {
        progress_tx: tx.clone(),
    });

    let app = Router::new()
        .route("/ws", get(handle_websocket))
        .route("/ws/{scan_id}", get(scan_ws))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test assertion should succeed");
    let addr = listener
        .local_addr()
        .expect("test assertion should succeed");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = shutdown_rx.await;
    });

    tokio::spawn(async move {
        let _ = server.await;
    });

    (format!("ws://{}/ws", addr), tx, shutdown_tx)
}

async fn scan_ws(
    Path(scan_id): Path<String>,
    ws: WebSocketUpgrade,
    State(state): State<Arc<WsState>>,
) -> Response {
    handle_scan_websocket(ws, scan_id, State(state)).await
}

#[tokio::test]
async fn test_ws_broadcast_progress_messages() {
    let (url, tx, shutdown) = start_ws_server().await;

    let (mut socket, _response) = connect_async(&url)
        .await
        .expect("test assertion should succeed");

    let progress = ProgressMessage::new("scan-1", 42, "protocols");
    tx.send(progress).expect("test assertion should succeed");

    let msg = timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("test assertion should succeed")
        .expect("test assertion should succeed")
        .expect("test assertion should succeed");

    let text = msg.into_text().expect("test assertion should succeed");
    assert!(text.contains("\"scan_id\":\"scan-1\""));
    assert!(text.contains("\"msg_type\":\"progress\""));

    let _ = shutdown.send(());
}

#[tokio::test]
async fn test_ws_scan_specific_filters_and_closes() {
    let (base_url, tx, shutdown) = start_ws_server().await;
    let scan_url = base_url.replace("/ws", "/ws/scan-A");

    let (mut socket, _response) = connect_async(&scan_url)
        .await
        .expect("test assertion should succeed");

    // Initial connection message for scan-specific stream.
    let init_msg = timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("test assertion should succeed")
        .expect("test assertion should succeed")
        .expect("test assertion should succeed");
    let init_text = init_msg.into_text().expect("test assertion should succeed");
    assert!(init_text.contains("\"type\":\"connected\""));

    // Send a message for a different scan_id; should not be forwarded.
    let other = ProgressMessage::new("scan-B", 10, "protocols");
    tx.send(other).expect("test assertion should succeed");

    let no_msg = timeout(Duration::from_millis(200), socket.next()).await;
    assert!(
        no_msg.is_err(),
        "unexpected message received for other scan"
    );

    // Now send a matching scan progress.
    let matching = ProgressMessage::new("scan-A", 55, "ciphers");
    tx.send(matching).expect("test assertion should succeed");

    let msg = timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("test assertion should succeed")
        .expect("test assertion should succeed")
        .expect("test assertion should succeed");
    let text = msg.into_text().expect("test assertion should succeed");
    assert!(text.contains("\"scan_id\":\"scan-A\""));
    assert!(text.contains("\"msg_type\":\"progress\""));

    // Send completion message; server should send completed and close shortly after.
    let completed = ProgressMessage::completed("scan-A");
    tx.send(completed).expect("test assertion should succeed");

    let first = timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("test assertion should succeed");

    let mut saw_close = false;
    if let Some(Ok(message)) = first {
        if message.is_close() {
            saw_close = true;
        } else {
            let text = message.into_text().expect("test assertion should succeed");
            assert!(text.contains("\"msg_type\":\"completed\""));
            let next = timeout(Duration::from_secs(2), socket.next())
                .await
                .expect("test assertion should succeed");
            saw_close = next
                .map(|res| res.expect("test assertion should succeed").is_close())
                .unwrap_or(true);
        }
    }

    assert!(saw_close, "expected close after completion");

    let _ = shutdown.send(());
}
