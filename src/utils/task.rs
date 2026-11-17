use tokio::task::JoinHandle;
use tracing::Instrument;

pub(crate) fn spawn_with_current_span<F>(future: F) -> JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future.instrument(tracing::Span::current()))
}

pub(crate) fn spawn_blocking_with_current_span<F, R>(f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let span = tracing::Span::current();
    let dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || span.in_scope(f))
    })
}

#[cfg(test)]
mod tests {
    use super::{spawn_blocking_with_current_span, spawn_with_current_span};
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    struct Buffer(Arc<Mutex<Vec<u8>>>);

    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufferWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buffer {
        type Writer = BufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            BufferWriter(self.0.clone())
        }
    }

    #[test]
    fn spawned_task_keeps_current_span() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(Buffer(output.clone()))
            .finish();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http.request", request_id = "request-123");
            runtime.block_on(async move {
                span.in_scope(|| {
                    spawn_with_current_span(async {
                        tracing::info!(event_name = "task.context.test", "task event");
                    })
                })
                .await
                .unwrap();
            });
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(output.lines().next().unwrap()).unwrap();
        assert_eq!(event["fields"]["event_name"], "task.context.test");
        assert_eq!(event["spans"][0]["request_id"], "request-123");
    }

    #[test]
    fn spawned_blocking_task_keeps_current_span() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(Buffer(output.clone()))
            .finish();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("scan.phase", phase = "blocking_probe");
            runtime.block_on(async move {
                span.in_scope(|| {
                    spawn_blocking_with_current_span(|| {
                        tracing::info!(event_name = "blocking_task.context.test", "task event");
                    })
                })
                .await
                .unwrap();
            });
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(output.lines().next().unwrap()).unwrap();
        assert_eq!(event["fields"]["event_name"], "blocking_task.context.test");
        assert_eq!(event["spans"][0]["phase"], "blocking_probe");
    }
}
