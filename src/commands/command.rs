// Command trait - Defines the interface for all command implementations
// Copyright (C) 2025 Marc Rivero (@seifreed)
// Licensed under GPL-3.0

use crate::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandExit {
    code: i32,
}

impl CommandExit {
    pub const fn success() -> Self {
        Self { code: 0 }
    }

    pub const fn failure(code: i32) -> Self {
        Self { code }
    }

    pub const fn code(self) -> i32 {
        self.code
    }

    pub const fn is_success(self) -> bool {
        self.code == 0
    }
}

/// Command trait - Defines the interface for all command implementations
///
/// This trait follows the Command Pattern to encapsulate different
/// operational modes of CipherRun as independent, testable command objects.
///
/// Each command is responsible for:
/// - Validating its own preconditions
/// - Executing its specific operational logic
/// - Handling errors appropriately
/// - Returning a Result indicating success or failure
///
/// # Design Principles
/// - Single Responsibility: Each command handles one operational mode
/// - Open/Closed: New commands can be added without modifying existing code
/// - Interface Segregation: Commands only depend on what they need
/// - Dependency Inversion: High-level main() depends on Command abstraction
///
/// # License
/// All implementations must be released under GNU General Public License v3 (GPLv3)
/// Author: Marc Rivero López
#[async_trait]
pub trait Command: Send + Sync {
    /// Execute the command asynchronously
    ///
    /// # Returns
    /// - `Ok(CommandExit)` with the desired process exit code if the command completed
    /// - `Err(anyhow::Error)` if the command failed
    ///
    /// # Errors
    /// Implementation-specific errors should be wrapped in TlsError
    /// with appropriate context to aid debugging
    async fn execute(&self) -> Result<CommandExit>;

    /// Get a human-readable name for this command (for logging/debugging)
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct DummyCommand;

    #[async_trait]
    impl Command for DummyCommand {
        async fn execute(&self) -> Result<CommandExit> {
            Ok(CommandExit::success())
        }

        fn name(&self) -> &'static str {
            "DummyCommand"
        }
    }

    #[tokio::test]
    async fn test_command_trait_execute_and_name() {
        let cmd = DummyCommand;
        assert_eq!(cmd.name(), "DummyCommand");
        let exit = cmd.execute().await.expect("command should succeed");
        assert!(exit.is_success());
    }
}
