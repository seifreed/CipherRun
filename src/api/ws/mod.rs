// WebSocket Module

pub mod progress;

pub use progress::handle_websocket;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_module_reexport() {
        let _handler = handle_websocket;
        let _ = _handler;
    }
}
