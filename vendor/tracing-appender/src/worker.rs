use crate::Msg;
use crossbeam_channel::{Receiver, RecvError, TryRecvError};
use std::fmt::Debug;
use std::io::Write;
use std::{io, thread};

pub(crate) struct Worker<T: Write + Send + 'static> {
    writer: T,
    receiver: Receiver<Msg>,
    shutdown: Receiver<()>,
    io_failure_reported: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum WorkerState {
    Empty,
    Disconnected,
    Continue,
    Shutdown,
}

impl<T: Write + Send + 'static> Worker<T> {
    pub(crate) fn new(receiver: Receiver<Msg>, writer: T, shutdown: Receiver<()>) -> Worker<T> {
        Self {
            writer,
            receiver,
            shutdown,
            io_failure_reported: false,
        }
    }

    fn report_io_failure(&mut self, operation: &'static str) {
        if !self.io_failure_reported {
            crate::report_internal_error(
                "logging.worker.io_failed",
                operation,
                "destination_io",
                "io_error",
                "worker_continues",
            );
            self.io_failure_reported = true;
        }
    }

    fn handle_recv(&mut self, result: &Result<Msg, RecvError>) -> io::Result<WorkerState> {
        match result {
            Ok(Msg::Line(msg)) => {
                self.writer.write_all(msg)?;
                Ok(WorkerState::Continue)
            }
            Ok(Msg::Shutdown) => Ok(WorkerState::Shutdown),
            Err(_) => Ok(WorkerState::Disconnected),
        }
    }

    fn handle_try_recv(&mut self, result: &Result<Msg, TryRecvError>) -> io::Result<WorkerState> {
        match result {
            Ok(Msg::Line(msg)) => {
                self.writer.write_all(msg)?;
                Ok(WorkerState::Continue)
            }
            Ok(Msg::Shutdown) => Ok(WorkerState::Shutdown),
            Err(TryRecvError::Empty) => Ok(WorkerState::Empty),
            Err(TryRecvError::Disconnected) => Ok(WorkerState::Disconnected),
        }
    }

    /// Blocks on the first recv of each batch of logs, unless the
    /// channel is disconnected. Afterwards, grabs as many logs as
    /// it can off the channel, buffers them and attempts a flush.
    pub(crate) fn work(&mut self) -> io::Result<WorkerState> {
        // Worker thread yields here if receive buffer is empty
        let mut worker_state = match self.handle_recv(&self.receiver.recv()) {
            Ok(state) => state,
            Err(_) => {
                self.report_io_failure("write_log_line");
                WorkerState::Continue
            }
        };

        while worker_state == WorkerState::Continue {
            let try_recv_result = self.receiver.try_recv();
            let handle_result = self.handle_try_recv(&try_recv_result);
            worker_state = match handle_result {
                Ok(state) => state,
                Err(_) => {
                    self.report_io_failure("write_log_line");
                    WorkerState::Continue
                }
            };
        }
        if self.writer.flush().is_err() {
            self.report_io_failure("flush_log_output");
        }
        Ok(worker_state)
    }

    /// Creates a worker thread that processes a channel until it's disconnected
    pub(crate) fn worker_thread(mut self, name: String) -> std::thread::JoinHandle<()> {
        thread::Builder::new()
            .name(name)
            .spawn(move || {
                loop {
                    match self.work() {
                        Ok(WorkerState::Continue) | Ok(WorkerState::Empty) => {}
                        Ok(WorkerState::Shutdown) | Ok(WorkerState::Disconnected) => {
                            let _ = self.shutdown.recv();
                            break;
                        }
                        Err(_) => self.report_io_failure("process_log_output"),
                    }
                }
                if self.writer.flush().is_err() {
                    self.report_io_failure("flush_log_output");
                }
            })
            .expect("failed to spawn `tracing-appender` non-blocking worker thread")
    }
}
