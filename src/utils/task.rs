use tokio::task::JoinHandle;

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
