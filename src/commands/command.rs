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
    pub const OPERATIONAL_FAILURE: i32 = 1;
    pub const FINDINGS_FAILURE: i32 = 2;
    pub const POLICY_FAILURE: i32 = 3;
    pub const DRIFT_FAILURE: i32 = 4;

    pub const fn success() -> Self {
        Self { code: 0 }
    }

    pub const fn failure(code: i32) -> Self {
        Self { code }
    }

    pub const fn findings_failure() -> Self {
        Self::failure(Self::FINDINGS_FAILURE)
    }

    pub const fn policy_failure() -> Self {
        Self::failure(Self::POLICY_FAILURE)
    }

    pub const fn drift_failure() -> Self {
        Self::failure(Self::DRIFT_FAILURE)
    }

    pub const fn code(self) -> i32 {
        self.code
    }

    pub const fn is_success(self) -> bool {
        self.code == 0
    }
}

pub(crate) fn exit_for_result_list<T, U>(results: &[(T, Result<U>)]) -> CommandExit {
    if results.iter().any(|(_, result)| result.is_err()) {
        CommandExit::failure(CommandExit::OPERATIONAL_FAILURE)
    } else {
        CommandExit::success()
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
    /// - `Err(TlsError)` if the command failed
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

    #[test]
    fn test_exit_for_result_list_fails_when_any_result_failed() {
        let results = vec![
            ("ok", Ok(1)),
            ("bad", Err(crate::TlsError::Other("failed".to_string()))),
        ];

        assert_eq!(exit_for_result_list(&results).code(), 1);
    }

    #[test]
    fn automation_exit_codes_are_stable() {
        assert_eq!(CommandExit::success().code(), 0);
        assert_eq!(CommandExit::OPERATIONAL_FAILURE, 1);
        assert_eq!(CommandExit::findings_failure().code(), 2);
        assert_eq!(CommandExit::policy_failure().code(), 3);
        assert_eq!(CommandExit::drift_failure().code(), 4);
    }
}
