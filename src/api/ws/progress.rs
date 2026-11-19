use crate::api::models::response::ProgressMessage;
use crate::utils::task::spawn_with_current_span;
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{Instrument, Span, debug, error, info, trace, warn};

/// AppState subset for WebSocket
pub struct WsState {
    pub progress_tx: broadcast::Sender<ProgressMessage>,
    pub ping_interval_seconds: u64,
}

/// Handle WebSocket upgrade
pub async fn handle_websocket(ws: WebSocketUpgrade, State(state): State<Arc<WsState>>) -> Response {
    let span = Span::current();
    ws.on_upgrade(move |socket| websocket_handler(socket, state).instrument(span))
}

/// WebSocket handler
async fn websocket_handler(socket: WebSocket, state: Arc<WsState>) {
    info!(
        event_name = "websocket.connection.established",
        "WebSocket connection established"
    );

    let (mut sender, mut receiver) = socket.split();

    // Subscribe to progress updates
    let mut progress_rx = state.progress_tx.subscribe();
    let ping_interval_seconds = state.ping_interval_seconds;

    // Spawn task to send progress updates
    let mut send_task = spawn_with_current_span(async move {
        let mut ping_interval = tokio::time::interval(Duration::from_secs(ping_interval_seconds));
        ping_interval.tick().await;

        loop {
            tokio::select! {
                progress = progress_rx.recv() => {
                    match progress {
                        Ok(progress) => {
                            // Serialize progress message to JSON
                            let json = match serde_json::to_string(&progress) {
                                Ok(j) => j,
                                Err(_) => {
                                    error!(
                                        event_name = "websocket.progress.serialize.failed",
                                        error_type = "serialization",
                                        "Failed to serialize progress message"
                                    );
                                    continue;
                                }
                            };

                            // Send as text message
                            if sender.send(Message::Text(json.into())).await.is_err() {
                                debug!(event_name = "websocket.connection.closed", reason = "send_failed", "WebSocket client disconnected");
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            // Receiver fell behind; newer messages are still available
                            warn!(
                                event_name = "websocket.progress.lagged",
                                skipped_messages = skipped,
                                outcome = "continuing",
                                "WebSocket progress receiver lagged"
                            );
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = ping_interval.tick() => {
                    if sender.send(Message::Ping(Vec::new().into())).await.is_err() {
                        debug!(event_name = "websocket.connection.closed", reason = "ping_send_failed", "WebSocket client disconnected");
                        break;
                    }
                }
            }
        }
    });

    // Spawn task to receive messages from client (for ping/pong)
    let mut recv_task = spawn_with_current_span(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => {
                    debug!(
                        event_name = "websocket.close.received",
                        "WebSocket client sent close"
                    );
                    break;
                }
                Ok(Message::Ping(_data)) => {
                    trace!(
                        event_name = "websocket.ping.received",
                        "WebSocket ping received"
                    );
                    // Axum automatically handles pong responses
                }
                Ok(Message::Pong(_)) => {
                    trace!(
                        event_name = "websocket.pong.received",
                        "WebSocket pong received"
                    );
                }
                Ok(Message::Text(text)) => {
                    trace!(
                        event_name = "websocket.text.received",
                        message_bytes = text.len(),
                        "Received WebSocket text message"
                    );
                    // Could handle client commands here
                }
                Err(_) => {
                    error!(
                        event_name = "websocket.receive.failed",
                        error_type = "websocket_transport",
                        "WebSocket connection failed"
                    );
                    break;
                }
                Ok(Message::Binary(_)) => {
                    trace!(
                        event_name = "websocket.binary.received",
                        "WebSocket binary frame received"
                    );
                }
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        result = (&mut send_task) => {
            if let Err(error) = result {
                error!(
                    event_name = "websocket.send_task.failed",
                    error_type = "join_error",
                    error_code = if error.is_panic() { "panic" } else { "other" },
                    "WebSocket send task failed"
                );
            }
            recv_task.abort();
        }
        result = (&mut recv_task) => {
            if let Err(error) = result {
                error!(
                    event_name = "websocket.receive_task.failed",
                    error_type = "join_error",
                    error_code = if error.is_panic() { "panic" } else { "other" },
                    "WebSocket receive task failed"
                );
            }
            send_task.abort();
        }
    }

    info!(
        event_name = "websocket.connection.closed",
        "WebSocket connection closed"
    );
}

/// Handle WebSocket for specific scan
pub async fn handle_scan_websocket(
    ws: WebSocketUpgrade,
    scan_id: String,
    State(state): State<Arc<WsState>>,
) -> Response {
    let span = Span::current();
    ws.on_upgrade(move |socket| scan_websocket_handler(socket, scan_id, state).instrument(span))
}

/// WebSocket handler for specific scan
pub async fn scan_websocket_handler(socket: WebSocket, scan_id: String, state: Arc<WsState>) {
    info!(
        event_name = "websocket.scan.connection.established",
        scan_id = %scan_id,
        "WebSocket connection established for scan"
    );

    let (mut sender, mut receiver) = socket.split();

    // Subscribe to progress updates
    let mut progress_rx = state.progress_tx.subscribe();
    let ping_interval_seconds = state.ping_interval_seconds;

    // Send initial connection message
    let init_msg = serde_json::json!({
        "type": "connected",
        "scan_id": scan_id,
        "message": "Connected to scan progress stream"
    });

    if let Ok(json) = serde_json::to_string(&init_msg)
        && sender.send(Message::Text(json.into())).await.is_err()
    {
        debug!(
            event_name = "websocket.scan.connection.closed",
            scan_id = %scan_id,
            reason = "initial_message_send_failed",
            "WebSocket client disconnected before initial scan message"
        );
        return;
    }

    // Spawn task to send progress updates for this specific scan
    let scan_id_clone = scan_id.clone();
    let mut send_task = spawn_with_current_span(async move {
        let mut ping_interval = tokio::time::interval(Duration::from_secs(ping_interval_seconds));
        ping_interval.tick().await;

        loop {
            tokio::select! {
                progress = progress_rx.recv() => {
                    match progress {
                        Ok(progress) => {
                            // Filter messages for this scan only
                            if progress.scan_id != scan_id_clone {
                                continue;
                            }

                            // Serialize progress message to JSON
                            let json = match serde_json::to_string(&progress) {
                                Ok(j) => j,
                                Err(_) => {
                                    error!(
                                        event_name = "websocket.progress.serialize.failed",
                                        error_type = "serialization",
                                        "Failed to serialize progress message"
                                    );
                                    continue;
                                }
                            };

                            // Send as text message
                            if sender.send(Message::Text(json.into())).await.is_err() {
                                debug!(
                                    event_name = "websocket.scan.connection.closed",
                                    scan_id = %scan_id_clone,
                                    reason = "progress_send_failed",
                                    "WebSocket client disconnected"
                                );
                                break;
                            }

                            // Close connection on completion or failure
                            if progress.msg_type == "completed"
                                || progress.msg_type == "failed"
                                || progress.msg_type == "cancelled"
                            {
                                debug!(
                                    event_name = "websocket.scan.stream.completed",
                                    scan_id = %scan_id_clone,
                                    progress_type = %progress.msg_type,
                                    "Closing completed scan progress stream"
                                );
                                if sender.send(Message::Close(None)).await.is_err() {
                                    debug!(
                                        event_name = "websocket.scan.connection.closed",
                                        scan_id = %scan_id_clone,
                                        reason = "close_send_failed",
                                        "WebSocket client disconnected while closing scan stream"
                                    );
                                }
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            // The progress stream is shared across every scan; under load
                            // this per-scan receiver can fall far enough behind that the
                            // dropped span includes this scan's terminal "completed"/
                            // "failed" message. That message is emitted exactly once, so
                            // continuing here would block forever waiting for a message
                            // that will never arrive, leaking the connection. Notify the
                            // client that the stream lagged and close it so the client can
                            // reconnect or poll the REST scan-status endpoint for the
                            // final result.
                            warn!(
                                event_name = "websocket.scan.progress.lagged",
                                scan_id = %scan_id_clone,
                                skipped_messages = skipped,
                                outcome = "closed",
                                "Progress stream lagged; closing scan stream"
                            );
                            let notice = serde_json::json!({
                                "type": "lagged",
                                "scan_id": scan_id_clone,
                                "message": "Progress stream fell behind and was closed; \
                                            reconnect or poll the scan status endpoint for the final result",
                            });
                            if let Ok(json) = serde_json::to_string(&notice)
                                && sender.send(Message::Text(json.into())).await.is_err()
                            {
                                debug!(
                                    event_name = "websocket.scan.connection.closed",
                                    scan_id = %scan_id_clone,
                                    reason = "lag_notice_send_failed",
                                    "WebSocket client disconnected while sending lag notice"
                                );
                                break;
                            }
                            if sender.send(Message::Close(None)).await.is_err() {
                                debug!(
                                    event_name = "websocket.scan.connection.closed",
                                    scan_id = %scan_id_clone,
                                    reason = "lag_close_send_failed",
                                    "WebSocket client disconnected while closing lagged scan stream"
                                );
                            }
                            break;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = ping_interval.tick() => {
                    if sender.send(Message::Ping(Vec::new().into())).await.is_err() {
                        debug!(
                            event_name = "websocket.scan.connection.closed",
                            scan_id = %scan_id_clone,
                            reason = "ping_send_failed",
                            "WebSocket client disconnected"
                        );
                        break;
                    }
                }
            }
        }
    });

    // Spawn task to receive messages from client
    let scan_id_recv = scan_id.clone();
    let mut recv_task = spawn_with_current_span(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => {
                    debug!(event_name = "websocket.scan.close.received", scan_id = %scan_id_recv, "WebSocket client closed scan stream");
                    break;
                }
                Ok(Message::Ping(_)) => {
                    trace!(event_name = "websocket.scan.ping.received", scan_id = %scan_id_recv, "WebSocket ping received");
                }
                Ok(Message::Pong(_)) => {
                    trace!(event_name = "websocket.scan.pong.received", scan_id = %scan_id_recv, "WebSocket pong received");
                }
                Ok(Message::Text(text)) => {
                    trace!(
                        event_name = "websocket.scan.text.received",
                        scan_id = %scan_id_recv,
                        message_bytes = text.len(),
                        "Received WebSocket text message"
                    );
                }
                Err(_) => {
                    error!(
                        event_name = "websocket.receive.failed",
                        scan_id = %scan_id_recv,
                        error_type = "websocket_transport",
                        "WebSocket receive failed"
                    );
                    break;
                }
                Ok(Message::Binary(_)) => {
                    trace!(event_name = "websocket.scan.binary.received", scan_id = %scan_id_recv, "WebSocket binary frame received");
                }
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        result = (&mut send_task) => {
            if let Err(error) = result {
                error!(
                    event_name = "websocket.scan.send_task.failed",
                    scan_id = %scan_id,
                    error_type = "join_error",
                    error_code = if error.is_panic() { "panic" } else { "other" },
                    "Scan WebSocket send task failed"
                );
            }
            recv_task.abort();
        }
        result = (&mut recv_task) => {
            if let Err(error) = result {
                error!(
                    event_name = "websocket.scan.receive_task.failed",
                    scan_id = %scan_id,
                    error_type = "join_error",
                    error_code = if error.is_panic() { "panic" } else { "other" },
                    "Scan WebSocket receive task failed"
                );
            }
            send_task.abort();
        }
    }

    info!(
        event_name = "websocket.scan.connection.closed",
        scan_id = %scan_id,
        "WebSocket connection closed for scan"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::response::ProgressMessage;
    use axum::{Router, extract::Path, routing::get};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;

    async fn scan_websocket_route(
        ws: WebSocketUpgrade,
        Path(scan_id): Path<String>,
        State(state): State<Arc<WsState>>,
    ) -> Response {
        handle_scan_websocket(ws, scan_id, State(state)).await
    }

    async fn start_test_server(state: Arc<WsState>) -> (String, oneshot::Sender<()>) {
        let app = Router::new()
            .route("/{scan_id}", get(scan_websocket_route))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("address should resolve");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        (format!("ws://{addr}"), shutdown_tx)
    }

    async fn next_text(
        socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> serde_json::Value {
        let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("websocket message should arrive")
            .expect("websocket should remain open")
            .expect("websocket receive should succeed");
        let ClientMessage::Text(text) = message else {
            panic!("expected a text websocket frame, got {message:?}");
        };
        serde_json::from_str(&text).expect("websocket frame should contain JSON")
    }

    #[tokio::test]
    async fn test_ws_state_broadcast_sends_progress() {
        let (tx, mut rx) = broadcast::channel(8);
        let state = WsState {
            progress_tx: tx.clone(),
            ping_interval_seconds: 30,
        };

        let msg = ProgressMessage::new("scan1", 5, "stage");
        state.progress_tx.send(msg.clone()).expect("send ok");

        let received = rx.recv().await.expect("recv ok");
        assert_eq!(received.scan_id, "scan1");
        assert_eq!(received.progress, 5);
        assert_eq!(received.stage, "stage");
    }

    #[tokio::test]
    async fn test_scan_websocket_filters_other_scans_and_closes_when_complete() {
        let (tx, _) = broadcast::channel(8);
        let state = Arc::new(WsState {
            progress_tx: tx.clone(),
            ping_interval_seconds: 30,
        });
        let (url, shutdown) = start_test_server(state).await;
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("{url}/requested-scan"))
            .await
            .expect("websocket should connect");

        let connected = next_text(&mut socket).await;
        assert_eq!(connected["type"], "connected");
        assert_eq!(connected["scan_id"], "requested-scan");

        socket
            .send(ClientMessage::Ping(vec![1].into()))
            .await
            .expect("ping should send");
        let pong = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("server should answer the ping")
            .expect("websocket should remain open")
            .expect("pong receive should succeed");
        assert!(matches!(pong, ClientMessage::Pong(_)));
        socket
            .send(ClientMessage::Text("client command".into()))
            .await
            .expect("text frame should send");
        socket
            .send(ClientMessage::Binary(vec![1].into()))
            .await
            .expect("binary frame should send");
        socket
            .send(ClientMessage::Pong(vec![2].into()))
            .await
            .expect("pong frame should send");

        tx.send(ProgressMessage::new("other-scan", 10, "ignored"))
            .expect("other scan progress should broadcast");
        tx.send(ProgressMessage::new("requested-scan", 25, "running"))
            .expect("requested scan progress should broadcast");
        let progress = next_text(&mut socket).await;
        assert_eq!(progress["scan_id"], "requested-scan");
        assert_eq!(progress["progress"], 25);

        tx.send(ProgressMessage::completed("requested-scan"))
            .expect("completion should broadcast");
        let completed = next_text(&mut socket).await;
        assert_eq!(completed["msg_type"], "completed");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .expect("websocket should close after completion")
                .expect("close frame should be received")
                .expect("websocket receive should succeed"),
            ClientMessage::Close(_)
        ));

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn test_scan_websocket_reports_lag_and_closes() {
        let (tx, _) = broadcast::channel(1);
        let state = Arc::new(WsState {
            progress_tx: tx.clone(),
            ping_interval_seconds: 30,
        });
        let (url, shutdown) = start_test_server(state).await;
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("{url}/requested-scan"))
            .await
            .expect("websocket should connect");

        let connected = next_text(&mut socket).await;
        assert_eq!(connected["type"], "connected");

        for progress in 0..10 {
            tx.send(ProgressMessage::new("requested-scan", progress, "running"))
                .expect("progress should broadcast");
        }

        let lag_notice = next_text(&mut socket).await;
        assert_eq!(lag_notice["type"], "lagged");
        assert_eq!(lag_notice["scan_id"], "requested-scan");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .expect("lagged websocket should close")
                .expect("close frame should be received")
                .expect("websocket receive should succeed"),
            ClientMessage::Close(_)
        ));

        let _ = shutdown.send(());
    }
}
