use colored::*;

pub(crate) fn format_ssl_grade(grade: &crate::rating::Grade) -> ColoredString {
    use crate::rating::Grade;
    let grade_str = format!("Grade {}", grade);
    match grade {
        Grade::APlus | Grade::A => grade_str.green().bold(),
        Grade::AMinus | Grade::B => grade_str.blue().bold(),
        Grade::C => grade_str.yellow(),
        Grade::D | Grade::E => grade_str.yellow(),
        Grade::F | Grade::T | Grade::M => grade_str.red().bold(),
    }
}

pub(crate) fn format_http_grade(grade: &crate::http::tester::SecurityGrade) -> ColoredString {
    use crate::http::tester::SecurityGrade;
    let grade_str = format!("Grade {:?}", grade);
    match grade {
        SecurityGrade::A => grade_str.green().bold(),
        SecurityGrade::B => grade_str.blue().bold(),
        SecurityGrade::C => grade_str.yellow().bold(),
        SecurityGrade::D => grade_str.yellow(),
        SecurityGrade::F => grade_str.red().bold(),
    }
}

pub(crate) fn format_advanced_grade(grade: &crate::http::headers_advanced::Grade) -> ColoredString {
    use crate::http::headers_advanced::Grade;
    match grade {
        Grade::A => "Grade A".green().bold(),
        Grade::B => "Grade B".blue(),
        Grade::C => "Grade C".yellow(),
        Grade::D => "Grade D".yellow(),
        Grade::F => "Grade F".red().bold(),
    }
}

pub(crate) fn format_threat_level(threat_level: &str) -> ColoredString {
    match threat_level.to_lowercase().as_str() {
        "critical" => threat_level.red().bold(),
        "high" => threat_level.red(),
        "medium" => threat_level.yellow(),
        "low" => threat_level.green(),
        _ => threat_level.normal(),
    }
}
