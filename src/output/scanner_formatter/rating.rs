use super::{RatingResult, ScannerFormatter, format_ssl_grade};
use colored::*;

impl<'a> ScannerFormatter<'a> {
    /// Display SSL Labs rating results
    pub fn display_rating_results(&self, rating: &RatingResult) {
        self.print_section("SSL Labs Rating:", 50);

        let grade_colored = format_ssl_grade(&rating.grade);
        println!("\n  {}", grade_colored);
        println!("  {}", rating.grade.description().dimmed());
        println!("\n  Overall Score: {}/100", rating.score);

        self.display_rating_components(rating);
        self.display_rating_warnings(rating);

        println!();
    }

    /// Display rating component scores
    fn display_rating_components(&self, rating: &RatingResult) {
        println!("\n{}", self.section_header("  Component Scores:"));
        println!("    Certificate:    {}/100", rating.certificate_score);
        println!("    Protocols:      {}/100", rating.protocol_score);
        println!("    Key Exchange:   {}/100", rating.key_exchange_score);
        println!("    Cipher Strength: {}/100", rating.cipher_strength_score);
    }

    /// Display rating warnings
    fn display_rating_warnings(&self, rating: &RatingResult) {
        if self.warning_mode() == super::WarningMode::Off {
            return;
        }

        if !rating.warnings.is_empty() && self.warning_mode() != super::WarningMode::Batch {
            println!("\n{}", "  Warnings:".yellow());
            for warning in &rating.warnings {
                println!("    ! {}", warning.red());
            }
        }
    }
}
