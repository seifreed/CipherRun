use crate::ciphers::CipherSuite;

pub(crate) struct CipherPreferenceAnalyzer {
    first_choice: Option<u16>,
    second_choice: Option<u16>,
    third_choice: Option<u16>,
    cipher_hexcodes: Vec<u16>,
    reversed: Vec<u16>,
    rotated: Option<Vec<u16>>,
}

impl CipherPreferenceAnalyzer {
    pub(crate) fn new(
        first_choice: Option<u16>,
        second_choice: Option<u16>,
        third_choice: Option<u16>,
        cipher_hexcodes: Vec<u16>,
        reversed: Vec<u16>,
        rotated: Option<Vec<u16>>,
    ) -> Self {
        Self {
            first_choice,
            second_choice,
            third_choice,
            cipher_hexcodes,
            reversed,
            rotated,
        }
    }

    pub(crate) fn is_client_preference(&self) -> bool {
        let follows_original = self
            .first_choice
            .is_some_and(|c| self.cipher_hexcodes.first() == Some(&c));
        let follows_reversed = self
            .second_choice
            .is_some_and(|c| self.reversed.first() == Some(&c));
        let follows_rotated = match (&self.third_choice, &self.rotated) {
            (Some(third), Some(offered)) => offered.first() == Some(third),
            (None, None) => true, // Test not performed (e.g. only 2 ciphers) — don't penalize
            (None, Some(_)) => false, // Ciphers were offered but server didn't respond — can't confirm
            (Some(_), None) => false, // Malformed test data
        };

        follows_original && follows_reversed && follows_rotated
    }

    pub(crate) fn all_choices_same(&self) -> bool {
        match self.third_choice {
            Some(third) => {
                self.first_choice == self.second_choice && self.second_choice == Some(third)
            }
            None => self.first_choice == self.second_choice,
        }
    }

    pub(crate) fn mostly_same_different_positions(&self) -> bool {
        let (Some(second), Some(third)) = (self.second_choice, self.third_choice) else {
            return false;
        };

        if second != third {
            return false;
        }

        let pos_in_reversed = self.reversed.iter().position(|&c| c == second);
        let pos_in_rotated = self
            .rotated
            .as_ref()
            .and_then(|offered| offered.iter().position(|&c| c == second));

        matches!((pos_in_reversed, pos_in_rotated), (Some(pos2), Some(pos3)) if pos2 != pos3)
    }

    pub(crate) fn is_server_preference(&self) -> bool {
        if self.is_client_preference() {
            tracing::debug!(
                "Server respects client cipher preference (consistently picks client's first choice)"
            );
            return false;
        }

        if self.all_choices_same() {
            tracing::debug!("Server enforces cipher preference (chose same cipher in all tests)");
            return true;
        }

        if self.mostly_same_different_positions() {
            tracing::debug!(
                "Server enforces cipher preference (chose same cipher in multiple tests from different positions)"
            );
            return true;
        }

        tracing::debug!(
            "Server cipher preference unclear (mixed behavior detected, defaulting to unknown)"
        );
        false
    }

    /// Build an approximate server preference order.
    ///
    /// **Important:** Only positions 1-3 are determined by server probing.
    /// Remaining positions are in arbitrary client-offered order and do NOT
    /// reflect the server's actual preference. Full server preference detection
    /// would require iterative elimination probing.
    pub(crate) fn build_preference_order(&self, supported_ciphers: &[CipherSuite]) -> Vec<String> {
        let mut preference_order = Vec::new();

        // Place known server preferences first (from our probe results)
        if let Some(first) = self.first_choice {
            preference_order.push(format!("{:04x}", first));
        }
        if let Some(second) = self.second_choice {
            let hex = format!("{:04x}", second);
            if !preference_order.contains(&hex) {
                preference_order.push(hex);
            }
        }
        if let Some(third) = self.third_choice {
            let hex = format!("{:04x}", third);
            if !preference_order.contains(&hex) {
                preference_order.push(hex);
            }
        }

        // Append remaining supported ciphers (order is client-provided, not server preference)
        for cipher in supported_ciphers {
            let hex = cipher.hexcode.to_lowercase();
            if !preference_order
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&hex))
            {
                preference_order.push(cipher.hexcode.to_lowercase());
            }
        }

        preference_order
    }
}
