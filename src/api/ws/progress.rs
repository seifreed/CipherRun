// WebSocket Progress Streaming

use crate::api::models::response::ProgressMessage;
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info};

/// AppState subset for WebSocket
pub struct WsState {
    pub progress_tx: broadcast::Sender<ProgressMessage>,
}

/// Handle WebSocket upgrade
pub async fn handle_websocket(ws: WebSocketUpgrade, State(state): State<Arc<WsState>>) -> Response {
    ws.on_upgrade(move |socket| websocket_handler(socket, state))
}

/// WebSocket handler
async fn websocket_handler(socket: WebSocket, state: Arc<WsState>) {
    info!("WebSocket connection established");

    let (mut sender, mut receiver) = socket.split();

    // Subscribe to progress updates
    let mut progress_rx = state.progress_tx.subscribe();

    // Spawn task to send progress updates
    let mut send_task = tokio::spawn(async move {
        while let Ok(progress) = progress_rx.recv().await {
            // Serialize progress message to JSON
            let json = match serde_json::to_string(&progress) {
                Ok(j) => j,
                Err(e) => {
                    error!("Failed to serialize progress message: {}", e);
                    continue;
                }
            };

            // Send as text message
            if sender.send(Message::Text(json)).await.is_err() {
                debug!("Client disconnected");
                break;
            }
        }
    });

    // Spawn task to receive messages from client (for ping/pong)
    let mut recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => {
                    debug!("Client sent close message");
                    break;
                }
                Ok(Message::Ping(_data)) => {
                    debug!("Received ping, sending pong");
                    // Axum automatically handles pong responses
                }
                Ok(Message::Pong(_)) => {
                    debug!("Received pong");
                }
                Ok(Message::Text(text)) => {
                    debug!("Received text message: {}", text);
                    // Could handle client commands here
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
        }
        _ = (&mut recv_task) => {
            send_task.abort();
        }
    }

    info!("WebSocket connection closed");
}

/// Handle WebSocket for specific scan
pub async fn handle_scan_websocket(
    ws: WebSocketUpgrade,
    scan_id: String,
    State(state): State<Arc<WsState>>,
) -> Response {
    ws.on_upgrade(move |socket| scan_websocket_handler(socket, scan_id, state))
}

/// WebSocket handler for specific scan
pub async fn scan_websocket_handler(socket: WebSocket, scan_id: String, state: Arc<WsState>) {
    info!("WebSocket connection established for scan: {}", scan_id);

    let (mut sender, mut receiver) = socket.split();

    // Subscribe to progress updates
    let mut progress_rx = state.progress_tx.subscribe();

    // Send initial connection message
    let init_msg = serde_json::json!({
        "type": "connected",
        "scan_id": scan_id,
        "message": "Connected to scan progress stream"
    });

    if let Ok(json) = serde_json::to_string(&init_msg) {
        let _ = sender.send(Message::Text(json)).await;
    }

    // Spawn task to send progress updates for this specific scan
    let scan_id_clone = scan_id.clone();
    let mut send_task = tokio::spawn(async move {
        while let Ok(progress) = progress_rx.recv().await {
            // Filter messages for this scan only
            if progress.scan_id != scan_id_clone {
                continue;
            }

            // Serialize progress message to JSON
            let json = match serde_json::to_string(&progress) {
                Ok(j) => j,
                Err(e) => {
                    error!("Failed to serialize progress message: {}", e);
                    continue;
                }
            };

            // Send as text message
            if sender.send(Message::Text(json)).await.is_err() {
                debug!("Client disconnected");
                break;
            }

            // Close connection on completion or failure
            if progress.msg_type == "completed" || progress.msg_type == "failed" {
                debug!("Scan {} finished, closing WebSocket", scan_id_clone);
                let _ = sender.send(Message::Close(None)).await;
                break;
            }
        }
    });

    // Spawn task to receive messages from client
    let mut recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => {
                    debug!("Client sent close message");
                    break;
                }
                Ok(Message::Ping(_)) => {
                    debug!("Received ping");
                }
                Ok(Message::Text(text)) => {
                    debug!("Received text message: {}", text);
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
        }
        _ = (&mut recv_task) => {
            send_task.abort();
        }
    }

    info!("WebSocket connection closed for scan: {}", scan_id);
}
