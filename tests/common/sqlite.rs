#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn unique_sqlite_db_path(prefix: &str) -> PathBuf {
    let counter = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    #[cfg(unix)]
    let path = PathBuf::from(format!("/tmp/{}-{}-{}-{}.db", prefix, pid, nanos, counter));

    #[cfg(not(unix))]
    let path = std::env::temp_dir().join(format!("{}-{}-{}-{}.db", prefix, pid, nanos, counter));

    let _ = std::fs::remove_file(&path);
    path
}
