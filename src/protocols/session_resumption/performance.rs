use super::SessionResumptionTester;
use crate::Result;
use std::time::Instant;

impl SessionResumptionTester {
    pub(super) async fn measure_performance_gain(&self) -> Result<f64> {
        let target = self.target.clone();
        let gain = tokio::task::spawn_blocking(move || {
            let tester = SessionResumptionTester { target };
            tester.measure_performance_gain_sync()
        })
        .await
        .map_err(|err| anyhow::anyhow!("Performance gain join error: {err}"))??;

        Ok(gain)
    }

    fn measure_performance_gain_sync(&self) -> Result<f64> {
        let full_handshake_times: Vec<f64> = (0..5)
            .filter_map(|_| {
                let start = Instant::now();
                if self.perform_full_handshake_sync().is_ok() {
                    Some(start.elapsed().as_secs_f64())
                } else {
                    None
                }
            })
            .collect();

        if full_handshake_times.is_empty() {
            return Ok(0.0);
        }

        let avg_full = full_handshake_times.iter().sum::<f64>() / full_handshake_times.len() as f64;

        let resumed_handshake_times: Vec<f64> = (0..5)
            .filter_map(|_| {
                let session = self.establish_session_sync().ok().flatten()?;
                let start = Instant::now();
                if self.resume_with_session_sync(&session).ok()? {
                    Some(start.elapsed().as_secs_f64())
                } else {
                    None
                }
            })
            .collect();

        if resumed_handshake_times.is_empty() {
            return Ok(0.0);
        }

        let avg_resumed =
            resumed_handshake_times.iter().sum::<f64>() / resumed_handshake_times.len() as f64;

        let improvement = if avg_full > 0.0 {
            ((avg_full - avg_resumed) / avg_full) * 100.0
        } else {
            0.0
        };

        Ok(improvement)
    }

    fn perform_full_handshake_sync(&self) -> Result<()> {
        self.establish_session_sync().map(|_| ())
    }
}
