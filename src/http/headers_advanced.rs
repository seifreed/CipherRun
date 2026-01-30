// Advanced HTTP Security Headers Analysis
// HSTS, HPKP, Cookie flags, Date/Time, Banners, Reverse Proxy detection

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HSTS (HTTP Strict Transport Security) detailed analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsAnalysis {
    pub enabled: bool,
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub preload: bool,
    pub details: String,
    pub grade: Grade,
}

/// HPKP (HTTP Public Key Pinning) analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkpAnalysis {
    pub enabled: bool,
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub report_uri: Option<String>,
    pub pins: Vec<String>,
    pub backup_pins: Vec<String>,
    pub details: String,
}

/// Cookie security flags analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieAnalysis {
    pub cookies: Vec<CookieInfo>,
    pub secure_count: usize,
    pub httponly_count: usize,
    pub samesite_count: usize,
    pub insecure_count: usize,
    pub details: String,
    pub grade: Grade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<String>,
}

/// HTTP Date/Time check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateTimeCheck {
    pub server_date: Option<String>,
    pub skew_seconds: Option<i64>,
    pub synchronized: bool,
    pub details: String,
}

/// Application banner detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerDetection {
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub application: Option<String>,
    pub framework: Option<String>,
    pub version_exposed: bool,
    pub details: String,
    pub grade: Grade,
}

/// Reverse proxy detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseProxyDetection {
    pub detected: bool,
    pub via_header: Option<String>,
    pub x_forwarded_for: bool,
    pub x_real_ip: bool,
    pub x_forwarded_proto: bool,
    pub proxy_type: Option<String>,
    pub details: String,
}

/// Security grade
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    pub fn as_str(&self) -> &'static str {
        match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        }
    }
}

/// Parse HSTS header
pub fn parse_hsts(headers: &HashMap<String, String>) -> HstsAnalysis {
    if let Some(hsts) = headers.get("strict-transport-security") {
        let mut max_age = None;
        let mut include_subdomains = false;
        let mut preload = false;

        // Parse directives
        for part in hsts.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("max-age=") {
                if let Ok(age) = value.parse::<u64>() {
                    max_age = Some(age);
                }
            } else if part.eq_ignore_ascii_case("includesubdomains") {
                include_subdomains = true;
            } else if part.eq_ignore_ascii_case("preload") {
                preload = true;
            }
        }

        let grade = grade_hsts(max_age, include_subdomains, preload);
        let details = format_hsts_details(max_age, include_subdomains, preload);

        HstsAnalysis {
            enabled: true,
            max_age,
            include_subdomains,
            preload,
            details,
            grade,
        }
    } else {
        HstsAnalysis {
            enabled: false,
            max_age: None,
            include_subdomains: false,
            preload: false,
            details: "HSTS not enabled - connections can be downgraded to HTTP".to_string(),
            grade: Grade::F,
        }
    }
}

fn grade_hsts(max_age: Option<u64>, include_subdomains: bool, preload: bool) -> Grade {
    match max_age {
        Some(age) if age >= 31536000 && include_subdomains && preload => Grade::A,
        Some(age) if age >= 31536000 && include_subdomains => Grade::B,
        Some(age) if age >= 15768000 => Grade::C,
        Some(_) => Grade::D,
        None => Grade::F,
    }
}

fn format_hsts_details(max_age: Option<u64>, include_subdomains: bool, preload: bool) -> String {
    let mut parts = Vec::new();

    if let Some(age) = max_age {
        let days = age / 86400;
        parts.push(format!("max-age={} ({} days)", age, days));
    }

    if include_subdomains {
        parts.push("includeSubDomains".to_string());
    }

    if preload {
        parts.push("preload".to_string());
    }

    if parts.is_empty() {
        "HSTS enabled but misconfigured".to_string()
    } else {
        format!("HSTS: {}", parts.join("; "))
    }
}

/// Parse HPKP header (deprecated but still checked)
pub fn parse_hpkp(headers: &HashMap<String, String>) -> HpkpAnalysis {
    if let Some(hpkp) = headers
        .get("public-key-pins")
        .or_else(|| headers.get("public-key-pins-report-only"))
    {
        let mut max_age = None;
        let mut include_subdomains = false;
        let mut report_uri = None;
        let mut pins = Vec::new();
        let mut backup_pins = Vec::new();

        for part in hpkp.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("max-age=") {
                if let Ok(age) = value.parse::<u64>() {
                    max_age = Some(age);
                }
            } else if part.eq_ignore_ascii_case("includesubdomains") {
                include_subdomains = true;
            } else if let Some(value) = part.strip_prefix("report-uri=") {
                report_uri = Some(value.trim_matches('"').to_string());
            } else if let Some(value) = part.strip_prefix("pin-sha256=") {
                pins.push(value.trim_matches('"').to_string());
            }
        }

        // Separate backup pins (just informational)
        if pins.len() > 1 {
            backup_pins = pins[1..].to_vec();
        }

        let details =
            "HPKP enabled (DEPRECATED - use Certificate Transparency instead)".to_string();

        HpkpAnalysis {
            enabled: true,
            max_age,
            include_subdomains,
            report_uri,
            pins: if pins.is_empty() {
                Vec::new()
            } else {
                vec![pins[0].clone()]
            },
            backup_pins,
            details,
        }
    } else {
        HpkpAnalysis {
            enabled: false,
            max_age: None,
            include_subdomains: false,
            report_uri: None,
            pins: Vec::new(),
            backup_pins: Vec::new(),
            details: "HPKP not enabled (good - it's deprecated)".to_string(),
        }
    }
}

/// Parse Set-Cookie headers for security flags
pub fn parse_cookies(set_cookie_headers: &[String]) -> CookieAnalysis {
    let mut cookies = Vec::new();
    let mut secure_count = 0;
    let mut httponly_count = 0;
    let mut samesite_count = 0;
    let mut insecure_count = 0;

    for cookie_str in set_cookie_headers {
        let cookie = parse_single_cookie(cookie_str);

        if cookie.secure {
            secure_count += 1;
        }
        if cookie.httponly {
            httponly_count += 1;
        }
        if cookie.samesite.is_some() {
            samesite_count += 1;
        }
        if !cookie.secure || !cookie.httponly || cookie.samesite.is_none() {
            insecure_count += 1;
        }

        cookies.push(cookie);
    }

    let grade = if insecure_count == 0 && !cookies.is_empty() {
        Grade::A
    } else if insecure_count < cookies.len() / 2 {
        Grade::B
    } else if insecure_count < cookies.len() {
        Grade::C
    } else {
        Grade::F
    };

    let details = format!(
        "{} cookie(s): {} Secure, {} HttpOnly, {} SameSite, {} insecure",
        cookies.len(),
        secure_count,
        httponly_count,
        samesite_count,
        insecure_count
    );

    CookieAnalysis {
        cookies,
        secure_count,
        httponly_count,
        samesite_count,
        insecure_count,
        details,
        grade,
    }
}

fn parse_single_cookie(cookie_str: &str) -> CookieInfo {
    let parts: Vec<&str> = cookie_str.split(';').collect();

    let name = if let Some(name_value) = parts.first() {
        name_value
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    } else {
        "unknown".to_string()
    };

    let mut secure = false;
    let mut httponly = false;
    let mut samesite = None;
    let mut domain = None;
    let mut path = None;
    let mut expires = None;

    for part in parts.iter().skip(1) {
        let part = part.trim();
        if part.eq_ignore_ascii_case("Secure") {
            secure = true;
        } else if part.eq_ignore_ascii_case("HttpOnly") {
            httponly = true;
        } else if let Some(value) = part.strip_prefix("SameSite=") {
            samesite = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("Domain=") {
            domain = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("Path=") {
            path = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("Expires=") {
            expires = Some(value.to_string());
        }
    }

    CookieInfo {
        name,
        secure,
        httponly,
        samesite,
        domain,
        path,
        expires,
    }
}

/// Check HTTP Date/Time
pub fn check_datetime(headers: &HashMap<String, String>) -> DateTimeCheck {
    if let Some(date_str) = headers.get("date") {
        // Parse HTTP date format
        if let Ok(server_time) = chrono::DateTime::parse_from_rfc2822(date_str) {
            let now = chrono::Utc::now();
            let skew = (server_time.timestamp() - now.timestamp()).abs();

            let synchronized = skew < 300; // Within 5 minutes

            let details = if synchronized {
                format!("Server time synchronized (skew: {} seconds)", skew)
            } else {
                format!(
                    "Server time NOT synchronized (skew: {} seconds, {} minutes)",
                    skew,
                    skew / 60
                )
            };

            return DateTimeCheck {
                server_date: Some(date_str.clone()),
                skew_seconds: Some(skew),
                synchronized,
                details,
            };
        }
    }

    DateTimeCheck {
        server_date: None,
        skew_seconds: None,
        synchronized: false,
        details: "No Date header found".to_string(),
    }
}

/// Detect application banners
pub fn detect_banners(headers: &HashMap<String, String>) -> BannerDetection {
    let server = headers.get("server").cloned();
    let powered_by = headers.get("x-powered-by").cloned();
    let application = headers
        .get("x-aspnet-version")
        .or_else(|| headers.get("x-aspnetmvc-version"))
        .cloned();
    let framework = headers.get("x-framework").cloned();

    let version_exposed = server.as_ref().is_some_and(|s| s.contains('/'))
        || powered_by.as_ref().is_some_and(|p| p.contains('/'))
        || application.is_some();

    let grade = if !version_exposed && server.is_none() && powered_by.is_none() {
        Grade::A
    } else if !version_exposed {
        Grade::B
    } else {
        Grade::F
    };

    let details = format!(
        "Server: {}, X-Powered-By: {}, Version exposed: {}",
        server.as_deref().unwrap_or("not disclosed"),
        powered_by.as_deref().unwrap_or("not disclosed"),
        version_exposed
    );

    BannerDetection {
        server,
        powered_by,
        application,
        framework,
        version_exposed,
        details,
        grade,
    }
}

/// Detect reverse proxy
pub fn detect_reverse_proxy(headers: &HashMap<String, String>) -> ReverseProxyDetection {
    let via_header = headers.get("via").cloned();
    let x_forwarded_for = headers.contains_key("x-forwarded-for");
    let x_real_ip = headers.contains_key("x-real-ip");
    let x_forwarded_proto = headers.contains_key("x-forwarded-proto");

    let detected = via_header.is_some() || x_forwarded_for || x_real_ip || x_forwarded_proto;

    let proxy_type = if let Some(ref via) = via_header {
        if via.contains("nginx") {
            Some("nginx".to_string())
        } else if via.contains("Apache") {
            Some("Apache".to_string())
        } else if via.contains("HAProxy") {
            Some("HAProxy".to_string())
        } else if via.contains("Varnish") {
            Some("Varnish".to_string())
        } else {
            Some("Unknown".to_string())
        }
    } else if x_forwarded_for {
        Some("Generic reverse proxy".to_string())
    } else {
        None
    };

    let details = if detected {
        let mut parts = Vec::new();
        if let Some(ref via) = via_header {
            parts.push(format!("Via: {}", via));
        }
        if x_forwarded_for {
            parts.push("X-Forwarded-For".to_string());
        }
        if x_real_ip {
            parts.push("X-Real-IP".to_string());
        }
        if x_forwarded_proto {
            parts.push("X-Forwarded-Proto".to_string());
        }
        format!("Reverse proxy detected: {}", parts.join(", "))
    } else {
        "No reverse proxy detected".to_string()
    };

    ReverseProxyDetection {
        detected,
        via_header,
        x_forwarded_for,
        x_real_ip,
        x_forwarded_proto,
        proxy_type,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hsts_full() {
        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000; includeSubDomains; preload".to_string(),
        );

        let hsts = parse_hsts(&headers);
        assert!(hsts.enabled);
        assert_eq!(hsts.max_age, Some(31536000));
        assert!(hsts.include_subdomains);
        assert!(hsts.preload);
        assert_eq!(hsts.grade, Grade::A);
    }

    #[test]
    fn test_parse_cookie_secure() {
        let cookies = vec!["session=abc123; Secure; HttpOnly; SameSite=Strict".to_string()];

        let analysis = parse_cookies(&cookies);
        assert_eq!(analysis.secure_count, 1);
        assert_eq!(analysis.httponly_count, 1);
        assert_eq!(analysis.samesite_count, 1);
        assert_eq!(analysis.insecure_count, 0);
    }

    #[test]
    fn test_detect_reverse_proxy() {
        let mut headers = HashMap::new();
        headers.insert("via".to_string(), "1.1 nginx".to_string());
        headers.insert("x-forwarded-for".to_string(), "192.168.1.1".to_string());

        let detection = detect_reverse_proxy(&headers);
        assert!(detection.detected);
        assert_eq!(detection.proxy_type, Some("nginx".to_string()));
    }
}
