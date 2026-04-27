use crate::api::models::response::{CertificateListResponse, CertificateSummary};
use chrono::{DateTime, Utc};

const SECONDS_PER_DAY: i64 = 86_400;

pub struct CertificateView {
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub san_json: Option<String>,
    pub hostnames: Vec<String>,
}

pub fn present_certificate_summary(view: CertificateView) -> CertificateSummary {
    let now = Utc::now();
    let days_until_expiry = signed_days_until_expiry(view.not_after, now);
    let is_expired = view.not_after < now;

    CertificateSummary {
        fingerprint: view.fingerprint,
        common_name: extract_cn_from_subject(&view.subject),
        san: parse_san(view.san_json.as_deref()),
        issuer: view.issuer,
        valid_from: view.not_before,
        valid_until: view.not_after,
        days_until_expiry,
        is_expired,
        is_expiring_soon: !is_expired && (0..30).contains(&days_until_expiry),
        hostnames: view.hostnames,
    }
}

fn signed_days_until_expiry(not_after: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    let seconds = (not_after - now).num_seconds();
    if seconds < 0 {
        let expired_days =
            seconds.saturating_abs().saturating_add(SECONDS_PER_DAY - 1) / SECONDS_PER_DAY;
        -expired_days
    } else {
        seconds / SECONDS_PER_DAY
    }
}

pub fn present_certificate_list(
    total: usize,
    offset: usize,
    limit: usize,
    certificates: Vec<CertificateSummary>,
) -> CertificateListResponse {
    CertificateListResponse {
        total,
        offset,
        limit,
        certificates,
    }
}

fn parse_san(san_json: Option<&str>) -> Vec<String> {
    san_json
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default()
}

fn extract_cn_from_subject(subject: &str) -> String {
    subject
        .split(',')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("CN"))
        .map(|(_, value)| value)
        .unwrap_or(subject)
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_extracts_common_name_and_expiry() {
        let now = Utc::now();
        let summary = present_certificate_summary(CertificateView {
            fingerprint: "fp".to_string(),
            subject: "C=US, O=Example, CN=example.com".to_string(),
            issuer: "Example CA".to_string(),
            not_before: now,
            not_after: now + chrono::Duration::days(10),
            san_json: Some("[\"example.com\",\"www.example.com\"]".to_string()),
            hostnames: vec!["example.com".to_string()],
        });

        assert_eq!(summary.common_name, "example.com");
        assert_eq!(summary.san.len(), 2);
        assert!(summary.is_expiring_soon);
    }

    #[test]
    fn summary_extracts_common_name_with_spaces_around_equals() {
        let now = Utc::now();
        let summary = present_certificate_summary(CertificateView {
            fingerprint: "fp".to_string(),
            subject: "C=US, O=Example, CN = spaced.example.com".to_string(),
            issuer: "Example CA".to_string(),
            not_before: now,
            not_after: now + chrono::Duration::days(10),
            san_json: None,
            hostnames: Vec::new(),
        });

        assert_eq!(summary.common_name, "spaced.example.com");
    }

    #[test]
    fn list_preserves_paging_metadata() {
        let response = present_certificate_list(5, 10, 20, Vec::new());
        assert_eq!(response.total, 5);
        assert_eq!(response.offset, 10);
        assert_eq!(response.limit, 20);
    }

    #[test]
    fn summary_handles_invalid_san_json_gracefully() {
        let now = Utc::now();
        let summary = present_certificate_summary(CertificateView {
            fingerprint: "fp".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "Example CA".to_string(),
            not_before: now,
            not_after: now + chrono::Duration::days(90),
            san_json: Some("not-json".to_string()),
            hostnames: Vec::new(),
        });

        assert!(summary.san.is_empty());
    }

    #[test]
    fn summary_marks_expired_certificates() {
        let now = Utc::now();
        let summary = present_certificate_summary(CertificateView {
            fingerprint: "expired".to_string(),
            subject: "CN=expired.example".to_string(),
            issuer: "Example CA".to_string(),
            not_before: now - chrono::Duration::days(90),
            not_after: now - chrono::Duration::days(1),
            san_json: Some("[]".to_string()),
            hostnames: vec!["expired.example".to_string()],
        });

        assert!(summary.is_expired);
        assert!(!summary.is_expiring_soon);
        assert!(summary.days_until_expiry < 0);
    }

    #[test]
    fn summary_marks_recently_expired_certificates_as_expired_not_expiring_soon() {
        let now = Utc::now();
        let summary = present_certificate_summary(CertificateView {
            fingerprint: "recently-expired".to_string(),
            subject: "CN=recently-expired.example".to_string(),
            issuer: "Example CA".to_string(),
            not_before: now - chrono::Duration::days(90),
            not_after: now - chrono::Duration::hours(1),
            san_json: Some("[]".to_string()),
            hostnames: vec!["recently-expired.example".to_string()],
        });

        assert!(summary.is_expired);
        assert!(!summary.is_expiring_soon);
        assert!(summary.days_until_expiry < 0);
    }

    #[test]
    fn summary_falls_back_when_subject_has_no_cn_separator() {
        let now = Utc::now();
        let subject = "example.com";
        let summary = present_certificate_summary(CertificateView {
            fingerprint: "fp".to_string(),
            subject: subject.to_string(),
            issuer: "Example CA".to_string(),
            not_before: now,
            not_after: now + chrono::Duration::days(120),
            san_json: None,
            hostnames: Vec::new(),
        });

        assert_eq!(summary.common_name, subject);
    }

    #[test]
    fn summary_preserves_empty_hostname_entries_from_input() {
        let now = Utc::now();
        let summary = present_certificate_summary(CertificateView {
            fingerprint: "fp".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "Example CA".to_string(),
            not_before: now,
            not_after: now + chrono::Duration::days(120),
            san_json: Some("[\"example.com\"]".to_string()),
            hostnames: vec!["".to_string(), "example.com".to_string()],
        });

        assert_eq!(summary.hostnames.len(), 2);
        assert_eq!(summary.hostnames[0], "");
    }
}
