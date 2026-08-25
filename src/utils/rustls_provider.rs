//! Process-level rustls provider selection.
//!
//! The full build opts into `ring`; reduced builds keep rustls' default
//! provider so they remain usable without the optional feature.

#[derive(Debug, Clone, Copy)]
pub struct ProviderInstallError;

impl std::fmt::Display for ProviderInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a rustls crypto provider is already installed")
    }
}

impl std::error::Error for ProviderInstallError {}

pub fn install_default() -> Result<(), ProviderInstallError> {
    #[cfg(feature = "rustls")]
    {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| ProviderInstallError)
    }

    #[cfg(not(feature = "rustls"))]
    {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .map_err(|_| ProviderInstallError)
    }
}

pub(crate) mod cipher_suite {
    #[cfg(feature = "rustls")]
    #[allow(unused_imports)]
    pub(crate) use rustls::crypto::ring::cipher_suite::*;

    #[cfg(not(feature = "rustls"))]
    #[allow(unused_imports)]
    pub(crate) use rustls::crypto::aws_lc_rs::cipher_suite::*;
}

#[cfg(test)]
mod tests {
    #[test]
    fn provider_selection_is_available() {
        let result = super::install_default();
        assert!(
            result.is_ok()
                || result
                    .unwrap_err()
                    .to_string()
                    .contains("already installed")
        );
    }
}
