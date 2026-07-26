/// Detect sensitive data patterns in HTTP response.
/// Uses precise matching to reduce false positives from comments/irrelevant text.
pub(super) fn detect_sensitive_patterns(response: &str) -> bool {
    let response_lower = response.to_lowercase();
    let headers_lower = response_lower
        .split_once("\r\n\r\n")
        .or_else(|| response_lower.split_once("\n\n"))
        .map_or(response_lower.as_str(), |(headers, _)| headers);

    if headers_lower.contains("set-cookie:") {
        return true;
    }

    if response_lower.contains("csrf-token=")
        || response_lower.contains("csrf_token=")
        || response_lower.contains("_csrf=")
        || response_lower.contains("name=\"csrf")
        || response_lower.contains("name='csrf")
        || response_lower.contains("csrfmiddlewaretoken")
    {
        return true;
    }

    if response_lower.contains("phpsessid=")
        || response_lower.contains("jsessionid=")
        || response_lower.contains("asp.net_sessionid=")
        || response_lower.contains("sessionid=")
        || response_lower.contains("session_id=")
        || response_lower.contains("name=\"session")
        || response_lower.contains("name='session")
    {
        return true;
    }

    if headers_lower.contains("authorization:")
        || headers_lower.contains("x-auth-token:")
        || headers_lower.contains("x-api-key:")
        || response_lower.contains("api_key=")
        || response_lower.contains("access_token=")
        || response_lower.contains("name=\"token")
        || response_lower.contains("name='token")
    {
        return true;
    }

    false
}

pub(super) fn is_compressed_encoding_header(line: &str) -> bool {
    let Some((name, value)) = line.split_once(':') else {
        return false;
    };
    if !name.eq_ignore_ascii_case("Content-Encoding") {
        return false;
    }

    value.split(',').map(str::trim).any(|token| {
        matches!(
            token.to_ascii_lowercase().as_str(),
            "gzip" | "deflate" | "br" | "zstd" | "compress"
        )
    })
}

pub(super) fn classify_dynamic_content_response(response: &str, marker: &str) -> Option<bool> {
    let status_line = response.strip_prefix("HTTP/")?;
    let status_code = status_line
        .split_once(' ')
        .map(|x| x.1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|code| code.parse::<u16>().ok())?;

    if (200..300).contains(&status_code) {
        Some(response.contains(marker))
    } else {
        Some(false)
    }
}
