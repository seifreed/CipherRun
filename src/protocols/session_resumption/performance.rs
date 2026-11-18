use super::SessionResumptionTester;
use crate::Result;
use crate::error::TlsError;
use std::{future::Future, time::Instant};

impl SessionResumptionTester {
    pub(super) async fn measure_performance_gain(&self) -> Result<f64> {
        measure_performance_gain_with(
            || self.establish_session(),
            |session| self.try_resume_with_session(session),
        )
        .await
    }
}

async fn measure_performance_gain_with<S, Establish, EstablishFuture, Resume, ResumeFuture>(
    mut establish_session: Establish,
    mut try_resume_with_session: Resume,
) -> Result<f64>
where
    Establish: FnMut() -> EstablishFuture,
    EstablishFuture: Future<Output = Result<Option<S>>>,
    Resume: FnMut(S) -> ResumeFuture,
    ResumeFuture: Future<Output = Result<bool>>,
{
    let mut full_handshake_times = Vec::new();
    let mut last_error = None;

    for _ in 0..5 {
        let start = Instant::now();
        match establish_session().await {
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
        let session = match establish_session().await {
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
        match try_resume_with_session(session).await {
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

    Ok(performance_improvement(avg_full, avg_resumed))
}

fn performance_improvement(avg_full: f64, avg_resumed: f64) -> f64 {
    if avg_full > 0.0 {
        ((avg_full - avg_resumed) / avg_full * 100.0).max(0.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::{measure_performance_gain_with, performance_improvement};
    use crate::TlsError;
    use std::time::Duration;

    #[tokio::test]
    async fn reports_error_when_no_full_handshake_succeeds() {
        let error = measure_performance_gain_with(
            || async { Err::<Option<()>, _>(TlsError::Other("offline".to_string())) },
            |_| async { Ok(false) },
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("no successful full handshakes; last error: offline")
        );
    }

    #[tokio::test]
    async fn reports_error_when_server_returns_no_resumable_session() {
        let error =
            measure_performance_gain_with(|| async { Ok(Some(())) }, |_| async { Ok(false) })
                .await
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("no successful resumed handshakes")
        );
    }

    #[tokio::test]
    async fn reports_error_when_resume_handshakes_fail() {
        let error = measure_performance_gain_with(
            || async { Ok(Some(())) },
            |_| async { Err::<bool, _>(TlsError::Other("resume failed".to_string())) },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("last error: resume failed"));
    }

    #[tokio::test]
    async fn reports_missing_sessions_after_full_handshakes() {
        let mut handshakes = 0;
        let error = measure_performance_gain_with(
            || {
                handshakes += 1;
                let session = (handshakes <= 5).then_some(());
                async move { Ok(session) }
            },
            |_| async { Ok(true) },
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("last error: server did not provide a resumable session")
        );
    }

    #[tokio::test]
    async fn returns_positive_gain_for_faster_resumed_handshakes() {
        let gain = measure_performance_gain_with(
            || async {
                tokio::time::sleep(Duration::from_millis(2)).await;
                Ok(Some(()))
            },
            |_| async { Ok(true) },
        )
        .await
        .unwrap();

        assert!(gain > 0.0);
    }

    #[tokio::test]
    async fn clamps_negative_gain_when_resumed_handshakes_are_slower() {
        let gain = measure_performance_gain_with(
            || async { Ok(Some(())) },
            |_| async {
                tokio::time::sleep(Duration::from_millis(2)).await;
                Ok(true)
            },
        )
        .await
        .unwrap();

        assert_eq!(gain, 0.0);
    }

    #[test]
    fn returns_zero_when_full_handshake_duration_is_zero() {
        assert_eq!(performance_improvement(0.0, 1.0), 0.0);
    }
}
