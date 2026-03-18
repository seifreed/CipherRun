// Logging Middleware

use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

/// Create logging layer for HTTP requests
pub fn logging_layer()
-> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>>
{
    TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_layer_is_cloneable() {
        let layer = logging_layer();
        let _ = layer.clone();
        let type_name = std::any::type_name_of_val(&layer);
        assert!(type_name.contains("TraceLayer"));
    }

    #[test]
    fn test_logging_layer_type_contains_classifier() {
        let layer = logging_layer();
        let type_name = std::any::type_name_of_val(&layer);
        assert!(type_name.contains("SharedClassifier"));
    }
}
