use colored::*;
use std::collections::HashMap;

use crate::protocols::intolerance::IntoleranceTestResult;

pub(crate) struct IntoleranceCheck<'a> {
    pub name: &'a str,
    pub is_intolerant: bool,
    pub inconclusive: bool,
    pub success_message: &'a str,
    pub failure_message: &'a str,
    pub detail_key: &'a str,
    pub is_critical: bool,
}

impl<'a> IntoleranceCheck<'a> {
    pub(crate) fn display(&self, details: &HashMap<String, String>) {
        if self.is_intolerant {
            let name_colored = if self.is_critical {
                self.name.red().bold()
            } else {
                self.name.red()
            };
            println!("\n{} {}", "X".red().bold(), name_colored);

            let message_colored = if self.is_critical {
                self.failure_message.red().bold()
            } else {
                self.failure_message.yellow()
            };
            println!("  {}", message_colored);

            if let Some(detail) = details.get(self.detail_key) {
                println!("  {}", detail.dimmed());
            }
        } else if self.inconclusive {
            println!("\n{} {}", "?".yellow().bold(), self.name.yellow());
            println!("  {}", "Test inconclusive".yellow());
            if let Some(detail) = details.get(self.detail_key) {
                println!("  {}", detail.dimmed());
            }
        } else {
            println!("\n{} {}", "Y".green(), self.name.green());
            println!("  {}", self.success_message);
        }
    }
}

pub(crate) fn build_intolerance_checks(
    results: &IntoleranceTestResult,
) -> Vec<IntoleranceCheck<'_>> {
    vec![
        IntoleranceCheck {
            name: "Extension Intolerance",
            is_intolerant: results.extension_intolerance,
            inconclusive: results
                .inconclusive_checks
                .iter()
                .any(|check| check == "extension_intolerance"),
            success_message: "Server properly handles TLS extensions",
            failure_message: "Server rejects ClientHellos with certain extensions",
            detail_key: "extension_intolerance",
            is_critical: false,
        },
        IntoleranceCheck {
            name: "Version Intolerance",
            is_intolerant: results.version_intolerance,
            inconclusive: results
                .inconclusive_checks
                .iter()
                .any(|check| check == "version_intolerance"),
            success_message: "Server properly handles version negotiation",
            failure_message: "Server rejects high version numbers in record layer",
            detail_key: "version_intolerance",
            is_critical: false,
        },
        IntoleranceCheck {
            name: "Long Handshake Intolerance",
            is_intolerant: results.long_handshake_intolerance,
            inconclusive: results
                .inconclusive_checks
                .iter()
                .any(|check| check == "long_handshake_intolerance"),
            success_message: "Server accepts long ClientHello messages",
            failure_message: "Server rejects ClientHello messages > 256 bytes",
            detail_key: "long_handshake_intolerance",
            is_critical: false,
        },
        IntoleranceCheck {
            name: "Incorrect SNI Alerts",
            is_intolerant: results.incorrect_sni_alerts,
            inconclusive: results
                .inconclusive_checks
                .iter()
                .any(|check| check == "incorrect_sni_alerts"),
            success_message: "Server sends correct alerts for SNI issues",
            failure_message: "Server sends wrong alert type for SNI failures",
            detail_key: "incorrect_sni_alerts",
            is_critical: false,
        },
        IntoleranceCheck {
            name: "Common DH Primes",
            is_intolerant: results.uses_common_dh_primes,
            inconclusive: results
                .inconclusive_checks
                .iter()
                .any(|check| check == "uses_common_dh_primes"),
            success_message: "Server does not use known weak DH primes",
            failure_message: "Server uses known weak DH primes (CRITICAL SECURITY ISSUE)",
            detail_key: "uses_common_dh_primes",
            is_critical: true,
        },
    ]
}
