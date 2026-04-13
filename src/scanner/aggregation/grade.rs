// CipherRun - Conservative Aggregation: Grade Aggregation
// Copyright (C) 2024 Marc Rivero López
// Licensed under GPL-3.0

use super::ConservativeAggregator;
use crate::rating::grader::Grade;

/// Map grade to rank where lower rank = worse grade (T→0, APlus→9).
/// Finding the minimum rank IS finding the worst grade.
fn grade_rank(grade: Grade) -> usize {
    match grade {
        Grade::T => 0,
        Grade::M => 1,
        Grade::F => 2,
        Grade::E => 3,
        Grade::D => 4,
        Grade::C => 5,
        Grade::B => 6,
        Grade::AMinus => 7,
        Grade::A => 8,
        Grade::APlus => 9,
    }
}

impl ConservativeAggregator {
    /// Aggregate grade conservatively - take the WORST grade across all IPs.
    ///
    /// The worst grade has the lowest rank number (see `grade_rank`), so
    /// we select the grade with the smallest rank. If two grades have the
    /// same rank, the one with the lower score is worse.
    pub(super) fn aggregate_grade_conservative(&self) -> (String, u8) {
        let mut worst_grade: Option<(String, u8, usize)> = None;

        for result in self.results.values() {
            if result.error.is_some() {
                continue;
            }

            if let Some(rating) = result.scan_result.ssl_rating() {
                let current_grade = (
                    format!("{}", rating.grade),
                    rating.score,
                    grade_rank(rating.grade),
                );

                match worst_grade {
                    None => worst_grade = Some(current_grade),
                    Some((ref _grade, score, rank)) => {
                        // Select lower rank (= worse grade), or same rank with lower score
                        if current_grade.2 < rank
                            || (current_grade.2 == rank && current_grade.1 < score)
                        {
                            worst_grade = Some(current_grade);
                        }
                    }
                }
            } else {
                // Backend completed successfully but has no rating — treat as worst case
                let current_grade = ("T".to_string(), 0, grade_rank(crate::rating::Grade::T));
                match worst_grade {
                    None => worst_grade = Some(current_grade),
                    Some((ref _grade, score, rank)) => {
                        if current_grade.2 < rank
                            || (current_grade.2 == rank && current_grade.1 < score)
                        {
                            worst_grade = Some(current_grade);
                        }
                    }
                }
            }
        }

        worst_grade
            .map(|(grade, score, _)| (grade, score))
            .unwrap_or_else(|| ("F".to_string(), 0))
    }
}
