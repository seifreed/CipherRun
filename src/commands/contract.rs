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
