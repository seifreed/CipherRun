# Local patch

This directory contains the upstream `tracing-appender` 0.2.5 crate, licensed
under MIT. The local changes route log rotation, retention, non-blocking write,
flush, and shutdown failures through stable WARN events. With an initialized
subscriber, events use `tracing`; before initialization they use a static
stderr fallback. Filesystem paths and raw OS error text are never emitted.

Rotation schedule, file naming, and retention behavior remain upstream
behavior. The non-blocking worker now reports its first I/O failure and keeps
consuming the queue so shutdown messages are still processed.
