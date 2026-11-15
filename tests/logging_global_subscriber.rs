use cipherrun::{Args, logging};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for CapturedOutput {
    type Writer = CapturedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedWriter(self.0.clone())
    }
}

impl Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn initialize_reuses_existing_global_subscriber() {
    let output = CapturedOutput(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(output.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("test process should not have a global subscriber yet");

    let guard = logging::initialize(&Args::default())
        .expect("existing host subscriber should keep the application running");
    drop(guard);

    let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("logging.subscriber.reused"), "{output}");
    assert!(output.contains("existing_subscriber"), "{output}");
}
