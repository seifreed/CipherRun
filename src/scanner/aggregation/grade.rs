// CipherRun - Conservative Aggregation: Grade Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;

impl ConservativeAggregator {
    /// Aggregate grade conservatively - take the WORST grade
    pub(super) fn aggregate_grade_conservative(&self) -> (String, u8) {
        let mut worst_grade: Option<(String, u8)> = None;

        for result in self.results.values() {
            if result.error.is_some() {
                continue;
            }

            if let Some(rating) = result.scan_result.ssl_rating() {
                let current_grade = (format!("{}", rating.grade), rating.score);

                match worst_grade {
                    None => worst_grade = Some(current_grade),
                    Some((ref _grade, score)) => {
                        if current_grade.1 < score {
                            worst_grade = Some(current_grade);
                        }
                    }
                }
            }
        }

        worst_grade.unwrap_or_else(|| ("F".to_string(), 0))
    }
}
