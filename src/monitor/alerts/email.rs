// Email Alert Channel - Using lettre

use crate::Result;
use crate::monitor::alerts::{Alert, AlertChannel, AlertType};
use crate::monitor::config::EmailConfig;
use async_trait::async_trait;
use lettre::message::{MultiPart, SinglePart, header};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

/// Email alert channel
pub struct EmailChannel {
    config: EmailConfig,
}

impl EmailChannel {
    /// Create new email channel
    pub fn new(config: EmailConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Build email message from alert
    fn build_message(&self, alert: &Alert) -> Result<Message> {
        let subject = format!(
            "[CipherRun] {} - {}",
            alert.severity.to_string().to_uppercase(),
            alert.hostname
        );

        let html_body = self.format_html_body(alert);
        let text_body = self.format_text_body(alert);

        let mut message_builder = Message::builder()
            .from(self.config.from_address.parse()?)
            .subject(subject);

        // Add all recipients
        for to_addr in &self.config.to_addresses {
            message_builder = message_builder.to(to_addr.parse()?);
        }

        let message = message_builder.multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )?;

        Ok(message)
    }

    /// Format alert as HTML
    fn format_html_body(&self, alert: &Alert) -> String {
        let severity_color = match alert.severity {
            crate::monitor::detector::ChangeSeverity::Critical => "#dc3545",
            crate::monitor::detector::ChangeSeverity::High => "#fd7e14",
            crate::monitor::detector::ChangeSeverity::Medium => "#ffc107",
            crate::monitor::detector::ChangeSeverity::Low => "#0dcaf0",
            crate::monitor::detector::ChangeSeverity::Info => "#6c757d",
        };

        let details_html = match &alert.alert_type {
            AlertType::CertificateChange { changes } => {
                let changes_html = changes
                    .iter()
                    .map(|change| {
                        format!(
                            "<li><strong>{:?}</strong>: {}</li>",
                            change.change_type, change.description
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("");

                format!("<h3>Certificate Changes</h3><ul>{}</ul>", changes_html)
            }
            AlertType::ExpiryWarning { days_remaining } => {
                format!(
                    "<h3>Certificate Expiry Warning</h3><p>Certificate expires in <strong>{}</strong> days.</p>",
                    days_remaining
                )
            }
            AlertType::ValidationFailure { reason } => {
                format!("<h3>Certificate Validation Failed</h3><p>{}</p>", reason)
            }
            AlertType::ScanFailure { error } => {
                format!("<h3>Scan Failed</h3><p>{}</p>", error)
            }
        };

        let cert_details = if let Some(ref serial) = alert.details.certificate_serial {
            format!(
                "<h3>Certificate Details</h3>
                <ul>
                    <li><strong>Serial:</strong> {}</li>
                    <li><strong>Issuer:</strong> {}</li>
                    <li><strong>Expiry:</strong> {}</li>
                </ul>",
                serial,
                alert
                    .details
                    .certificate_issuer
                    .as_deref()
                    .unwrap_or("Unknown"),
                alert
                    .details
                    .certificate_expiry
                    .as_deref()
                    .unwrap_or("Unknown")
            )
        } else {
            String::new()
        };

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: {}; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border-radius: 0 0 5px 5px; }}
        h1 {{ margin: 0; font-size: 24px; }}
        h3 {{ color: #555; margin-top: 20px; }}
        ul {{ padding-left: 20px; }}
        .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{} Alert</h1>
            <p style="margin: 5px 0 0 0;">{}</p>
        </div>
        <div class="content">
            <p><strong>Hostname:</strong> {}</p>
            <p><strong>Time:</strong> {}</p>
            {}
            {}
        </div>
        <div class="footer">
            <p>This alert was generated by CipherRun Certificate Monitoring</p>
        </div>
    </div>
</body>
</html>"#,
            severity_color,
            alert.severity.to_string().to_uppercase(),
            alert.message,
            alert.hostname,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            details_html,
            cert_details
        )
    }

    /// Format alert as plain text
    fn format_text_body(&self, alert: &Alert) -> String {
        let mut body = format!(
            "CipherRun Certificate Monitoring Alert\n\n\
            Severity: {}\n\
            Hostname: {}\n\
            Message: {}\n\
            Time: {}\n\n",
            alert.severity.to_string().to_uppercase(),
            alert.hostname,
            alert.message,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );

        match &alert.alert_type {
            AlertType::CertificateChange { changes } => {
                body.push_str("Certificate Changes:\n");
                for change in changes {
                    body.push_str(&format!(
                        "  - {:?}: {}\n",
                        change.change_type, change.description
                    ));
                }
            }
            AlertType::ExpiryWarning { days_remaining } => {
                body.push_str(&format!(
                    "Certificate expires in {} days.\n",
                    days_remaining
                ));
            }
            AlertType::ValidationFailure { reason } => {
                body.push_str(&format!("Validation failure: {}\n", reason));
            }
            AlertType::ScanFailure { error } => {
                body.push_str(&format!("Scan error: {}\n", error));
            }
        }

        if let Some(ref serial) = alert.details.certificate_serial {
            body.push_str(&format!(
                "\nCertificate Details:\n\
                Serial: {}\n\
                Issuer: {}\n\
                Expiry: {}\n",
                serial,
                alert
                    .details
                    .certificate_issuer
                    .as_deref()
                    .unwrap_or("Unknown"),
                alert
                    .details
                    .certificate_expiry
                    .as_deref()
                    .unwrap_or("Unknown")
            ));
        }

        body.push_str("\n---\nGenerated by CipherRun");

        body
    }

    /// Get SMTP transport
    fn get_transport(&self) -> Result<SmtpTransport> {
        let creds = Credentials::new(self.config.username.clone(), self.config.password.clone());

        let transport = if self.config.use_tls {
            SmtpTransport::starttls_relay(&self.config.smtp_server)?
        } else {
            SmtpTransport::relay(&self.config.smtp_server)?
        };

        let transport = transport
            .credentials(creds)
            .port(self.config.smtp_port)
            .build();

        Ok(transport)
    }
}

#[async_trait]
impl AlertChannel for EmailChannel {
    async fn send_alert(&self, alert: &Alert) -> Result<()> {
        let message = self.build_message(alert)?;
        let transport = self.get_transport()?;

        // Send email (blocking operation, run in blocking task)
        tokio::task::spawn_blocking(move || {
            transport
                .send(&message)
                .map_err(|e| anyhow::anyhow!("Failed to send email: {}", e))
        })
        .await??;

        Ok(())
    }

    fn channel_name(&self) -> &str {
        "email"
    }

    async fn test_connection(&self) -> Result<()> {
        let transport = self.get_transport()?;

        tokio::task::spawn_blocking(move || {
            transport
                .test_connection()
                .map_err(|e| anyhow::anyhow!("SMTP connection test failed: {}", e))
        })
        .await??;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::alerts::AlertDetails;
    use chrono::Utc;

    fn create_test_config() -> EmailConfig {
        EmailConfig {
            enabled: true,
            smtp_server: "smtp.example.com".to_string(),
            smtp_port: 587,
            from_address: "alerts@example.com".to_string(),
            to_addresses: vec!["admin@example.com".to_string()],
            username: "user".to_string(),
            password: "pass".to_string(),
            use_tls: true,
        }
    }

    #[test]
    fn test_email_channel_new() {
        let config = create_test_config();
        let channel = EmailChannel::new(config);
        assert!(channel.is_ok());
    }

    #[test]
    fn test_format_text_body() {
        let config = create_test_config();
        let channel = EmailChannel::new(config).unwrap();

        let alert =
            Alert::scan_failure("example.com".to_string(), "Connection refused".to_string());

        let body = channel.format_text_body(&alert);

        assert!(body.contains("example.com"));
        assert!(body.contains("Connection refused"));
        assert!(body.contains("CipherRun"));
    }

    #[test]
    fn test_format_html_body() {
        let config = create_test_config();
        let channel = EmailChannel::new(config).unwrap();

        let alert = Alert::expiry_warning(
            "example.com".to_string(),
            7,
            AlertDetails {
                certificate_serial: Some("123456".to_string()),
                certificate_issuer: Some("Let's Encrypt".to_string()),
                certificate_expiry: Some("2025-01-01".to_string()),
                previous_serial: None,
                scan_time: Utc::now(),
            },
        );

        let body = channel.format_html_body(&alert);

        assert!(body.contains("<!DOCTYPE html>"));
        assert!(body.contains("example.com"));
        assert!(body.contains("expires in"));
        assert!(body.contains("123456"));
    }

    #[test]
    fn test_channel_name() {
        let config = create_test_config();
        let channel = EmailChannel::new(config).unwrap();
        assert_eq!(channel.channel_name(), "email");
    }
}
