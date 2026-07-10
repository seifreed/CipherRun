use super::SessionResumptionTester;
use crate::Result;
use crate::error::TlsError;
use std::time::Instant;

impl SessionResumptionTester {
    pub(super) async fn measure_performance_gain(&self) -> Result<f64> {
        let mut full_handshake_times = Vec::new();
        let mut last_error = None;

        for _ in 0..5 {
            let start = Instant::now();
            match self.establish_session().await {
                Ok(_) => full_handshake_times.push(start.elapsed().as_secs_f64()),
                Err(error) => last_error = Some(error.to_string()),
            }
        }

        if full_handshake_times.is_empty() {
            return Err(TlsError::Other(format!(
                "no successful full handshakes{}",
                last_error
                    .map(|error| format!("; last error: {error}"))
                    .unwrap_or_default()
            )));
        }

        let avg_full = full_handshake_times.iter().sum::<f64>() / full_handshake_times.len() as f64;

        let mut resumed_handshake_times = Vec::new();
        let mut last_error = None;

        for _ in 0..5 {
            let session = match self.establish_session().await {
                Ok(Some(session)) => session,
                Ok(None) => {
                    last_error = Some("server did not provide a resumable session".to_string());
                    continue;
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                    continue;
                }
            };

            let start = Instant::now();
            match self.try_resume_with_session(session).await {
                Ok(true) => resumed_handshake_times.push(start.elapsed().as_secs_f64()),
                Ok(false) => last_error = Some("session was not reused".to_string()),
                Err(error) => last_error = Some(error.to_string()),
            }
        }

        if resumed_handshake_times.is_empty() {
            return Err(TlsError::Other(format!(
                "no successful resumed handshakes{}",
                last_error
                    .map(|error| format!("; last error: {error}"))
                    .unwrap_or_default()
            )));
        }

        let avg_resumed =
            resumed_handshake_times.iter().sum::<f64>() / resumed_handshake_times.len() as f64;

        let improvement = if avg_full > 0.0 {
            ((avg_full - avg_resumed) / avg_full * 100.0).max(0.0)
        } else {
            0.0
        };

        Ok(improvement)
    }
}
