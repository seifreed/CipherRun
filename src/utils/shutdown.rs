use std::io;

pub async fn shutdown_signal() -> io::Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                Ok("SIGINT")
            }
            _ = terminate.recv() => Ok("SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok("SIGINT")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::shutdown_signal;
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    fn assert_signal(signal: &str, expected: &str) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "utils::shutdown::tests::shutdown_signal_child",
                "--nocapture",
            ])
            .env("CIPHERRUN_SHUTDOWN_CHILD", expected)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "child exited early"
            );
            if line.contains("shutdown signal registered") {
                break;
            }
        }

        assert!(
            Command::new("kill")
                .args([format!("-{signal}"), child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn maps_sigterm_to_shutdown_outcome() {
        assert_signal("TERM", "SIGTERM");
    }

    #[test]
    fn maps_sigint_to_shutdown_outcome() {
        assert_signal("INT", "SIGINT");
    }

    #[tokio::test]
    async fn shutdown_signal_child() {
        let Ok(expected) = std::env::var("CIPHERRUN_SHUTDOWN_CHILD") else {
            return;
        };
        let shutdown = tokio::spawn(shutdown_signal());
        tokio::time::sleep(Duration::from_millis(20)).await;
        println!("shutdown signal registered");
        assert_eq!(shutdown.await.unwrap().unwrap(), expected);
    }
}
