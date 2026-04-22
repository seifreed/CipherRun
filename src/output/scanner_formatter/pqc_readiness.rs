use super::super::ScannerFormatter;
use crate::pqc::{PqcLevel, PqcReadinessAssessment};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    pub fn display_pqc_readiness_results(&self, assessment: &PqcReadinessAssessment) {
        self.print_section("Post-Quantum Cryptography Readiness:", 50);

        self.display_pqc_score(assessment.score, &assessment.level);

        if assessment.hndl_risk {
            println!(
                "\n  {} Harvest-Now-Decrypt-Later (HNDL) risk detected",
                "!".red().bold()
            );
            println!(
                "    {}",
                "Adversaries capturing traffic today can decrypt it once a quantum computer exists.".red()
            );
        }

        if !assessment.pq_safe_groups.is_empty() {
            println!("\n  PQC-safe key exchange groups:");
            for group in &assessment.pq_safe_groups {
                println!("    {} {}", "+".green().bold(), group.green());
            }
        }

        self.display_pqc_recommendations(assessment);
    }

    fn display_pqc_score(&self, score: u8, level: &PqcLevel) {
        let label = level.label();
        let score_str = format!("{}/100", score);
        let colored_score = match score {
            0..=24 => score_str.red().bold(),
            25..=49 => score_str.yellow().bold(),
            50..=74 => score_str.cyan().bold(),
            _ => score_str.green().bold(),
        };
        let colored_label = match level {
            PqcLevel::None => format!("[{}]", label).red(),
            PqcLevel::Partial => format!("[{}]", label).yellow(),
            PqcLevel::Hybrid => format!("[{}]", label).cyan(),
            PqcLevel::Full => format!("[{}]", label).green(),
        };
        println!("\n  Score: {} {}", colored_score, colored_label);
    }

    fn display_pqc_recommendations(&self, assessment: &PqcReadinessAssessment) {
        if !assessment.recommendations.is_empty() {
            println!("\n  Recommendations:");
            for rec in &assessment.recommendations {
                println!("    - {}", rec.yellow());
            }
        }
    }
}
