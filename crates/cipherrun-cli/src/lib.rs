//! Stable command exit contracts for CipherRun integrations.

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

#[cfg(test)]
mod tests {
    use super::CommandExit;

    #[test]
    fn command_exit_builders_preserve_codes_and_success_state() {
        let success = CommandExit::success();
        assert_eq!(success.code(), 0);
        assert!(success.is_success());

        let failures = [
            (
                CommandExit::failure(CommandExit::OPERATIONAL_FAILURE),
                CommandExit::OPERATIONAL_FAILURE,
            ),
            (
                CommandExit::findings_failure(),
                CommandExit::FINDINGS_FAILURE,
            ),
            (CommandExit::policy_failure(), CommandExit::POLICY_FAILURE),
            (CommandExit::drift_failure(), CommandExit::DRIFT_FAILURE),
            (CommandExit::failure(-1), -1),
        ];

        for (exit, expected_code) in failures {
            assert_eq!(exit.code(), expected_code);
            assert!(!exit.is_success());
        }
    }
}
