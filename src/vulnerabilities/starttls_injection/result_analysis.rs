use super::{StarttlsInjectionProtocol, StarttlsInjectionResult, StarttlsInjectionStatus};

pub(super) fn empty_result() -> StarttlsInjectionResult {
    StarttlsInjectionResult {
        vulnerable: false,
        smtp_vulnerable: false,
        imap_vulnerable: false,
        pop3_vulnerable: false,
        inconclusive: false,
        details: Vec::new(),
    }
}

pub(super) fn record_probe_status(
    result: &mut StarttlsInjectionResult,
    protocol: StarttlsInjectionProtocol,
    status: StarttlsInjectionStatus,
) {
    let protocol_name = protocol.name();
    match status {
        StarttlsInjectionStatus::Vulnerable => {
            result.vulnerable = true;
            mark_protocol_vulnerable(result, protocol);
            result.details.push(format!(
                "{} STARTTLS injection detected - commands can be injected before TLS upgrade",
                protocol_name
            ));
        }
        StarttlsInjectionStatus::NotVulnerable => {
            result
                .details
                .push(format!("{} STARTTLS injection not detected", protocol_name));
        }
        StarttlsInjectionStatus::Inconclusive => {
            result.inconclusive = true;
            result.details.push(format!(
                "{} STARTTLS injection test inconclusive - unable to complete probe",
                protocol_name
            ));
        }
    }
}

pub(super) fn record_probe_error(
    result: &mut StarttlsInjectionResult,
    protocol: StarttlsInjectionProtocol,
    error: &dyn std::fmt::Display,
) {
    result.inconclusive = true;
    result
        .details
        .push(format!("{} test error: {}", protocol.name(), error));
}

pub(super) fn record_nonstandard_port(result: &mut StarttlsInjectionResult, port: u16) {
    result.details.push(format!(
        "Port {} is not a standard STARTTLS port (25, 143, 110, 587)",
        port
    ));
}

fn mark_protocol_vulnerable(
    result: &mut StarttlsInjectionResult,
    protocol: StarttlsInjectionProtocol,
) {
    match protocol {
        StarttlsInjectionProtocol::Smtp => result.smtp_vulnerable = true,
        StarttlsInjectionProtocol::Imap => result.imap_vulnerable = true,
        StarttlsInjectionProtocol::Pop3 => result.pop3_vulnerable = true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_smtp_marks_overall_and_protocol_flags() {
        let mut result = empty_result();

        record_probe_status(
            &mut result,
            StarttlsInjectionProtocol::Smtp,
            StarttlsInjectionStatus::Vulnerable,
        );

        assert!(result.vulnerable);
        assert!(result.smtp_vulnerable);
        assert!(!result.imap_vulnerable);
    }

    #[test]
    fn inconclusive_probe_marks_inconclusive() {
        let mut result = empty_result();

        record_probe_status(
            &mut result,
            StarttlsInjectionProtocol::Imap,
            StarttlsInjectionStatus::Inconclusive,
        );

        assert!(result.inconclusive);
        assert!(result.details[0].contains("IMAP"));
    }

    #[test]
    fn nonstandard_port_adds_detail_only() {
        let mut result = empty_result();

        record_nonstandard_port(&mut result, 9999);

        assert!(!result.vulnerable);
        assert!(result.details[0].contains("not a standard STARTTLS port"));
    }
}
