/// Check if a response code appears at the start of any protocol response line.
pub(super) fn has_code_at_line_start(response: &str, code: &str) -> bool {
    response.lines().any(|line| line.starts_with(code))
}

/// Find the byte position of a response code at the start of a line.
pub(super) fn find_code_at_line_start(response: &str, code: &str) -> Option<usize> {
    let mut pos = 0;
    for line in response.lines() {
        if let Some(after) = line.strip_prefix(code)
            && (after.is_empty() || after.starts_with(' ') || after.starts_with('-'))
        {
            return Some(pos);
        }
        pos += line.len() + 1;
    }
    None
}

pub(super) fn has_ascii_token(response: &str, token: &str) -> bool {
    response
        .lines()
        .any(|line| line_has_ascii_token(line, token))
}

pub(super) fn has_multiple_pop3_ok_lines(response: &str) -> bool {
    response
        .lines()
        .filter(|line| line.starts_with("+OK"))
        .count()
        >= 2
}

fn line_has_ascii_token(line: &str, token: &str) -> bool {
    line.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|part| part.eq_ignore_ascii_case(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_codes_only_at_line_start() {
        let response = "220 ready\r\nhost250.example\r\n250 OK\r\n";
        assert_eq!(find_code_at_line_start(response, "250"), Some(26));
        assert!(has_code_at_line_start(response, "220"));
    }

    #[test]
    fn ascii_token_respects_boundaries_and_case() {
        assert!(has_ascii_token(
            "* CAPABILITY imap4rev1 STARTTLS\r\n",
            "starttls"
        ));
        assert!(!has_ascii_token("* CAPABILITY XSTARTTLSY\r\n", "STARTTLS"));
    }

    #[test]
    fn pop3_ok_requires_two_positive_lines() {
        assert!(!has_multiple_pop3_ok_lines(
            "+OK Begin TLS\r\n-ERR nope\r\n"
        ));
        assert!(has_multiple_pop3_ok_lines(
            "+OK Begin TLS\r\n+OK user accepted\r\n"
        ));
    }
}
