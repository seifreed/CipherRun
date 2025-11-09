# CipherRun Certificate Monitoring

Complete 24/7 certificate monitoring system with multi-channel alerting.

## Features

- **Continuous Monitoring**: 24/7 automated certificate scanning
- **Change Detection**: Detects renewals, issuer changes, SAN modifications
- **Expiry Warnings**: Configurable alerts at 30, 14, 7, and 1 day thresholds
- **Multi-Channel Alerts**: Email, Slack, Teams, PagerDuty, and custom webhooks
- **Smart Scheduling**: Jittered intervals to prevent thundering herd
- **Graceful Shutdown**: Clean SIGTERM/SIGINT handling
- **Alert Deduplication**: Prevents alert spam with configurable windows
- **Database Integration**: Optional scan history storage (PostgreSQL/SQLite)

## Quick Start

### 1. Basic Setup

```bash
# Create configuration
cp examples/monitor.toml /etc/cipherrun/monitor.toml
cp examples/domains.txt /etc/cipherrun/domains.txt

# Edit configuration
vim /etc/cipherrun/monitor.toml
vim /etc/cipherrun/domains.txt

# Start monitoring
cipherrun monitor --config /etc/cipherrun/monitor.toml \
                  --domains /etc/cipherrun/domains.txt
```

### 2. Test Alert Channels

```bash
# Test all configured alert channels
cipherrun monitor --test-alerts --config /etc/cipherrun/monitor.toml
```

### 3. Single Domain Monitoring

```bash
# Monitor a single domain with 1-hour interval
cipherrun monitor --domain example.com --interval 1h
```

## Configuration

### Monitor Settings

```toml
[monitor]
default_interval_seconds = 3600  # Default scan interval
max_concurrent_scans = 10        # Max parallel scans

# Optional database for scan history
database_url = "postgres://user:pass@localhost/cipherrun"
```

### Alert Thresholds

```toml
[monitor.thresholds]
expiry_30d = true              # Alert at 30 days before expiry
expiry_14d = true              # Alert at 14 days
expiry_7d = true               # Alert at 7 days
expiry_1d = true               # Alert at 1 day
on_certificate_change = true   # Alert on any certificate change
```

### Email Alerts

```toml
[monitor.alerts.email]
enabled = true
smtp_server = "smtp.gmail.com"
smtp_port = 587
from_address = "alerts@example.com"
to_addresses = ["security@example.com"]
username = "alerts@example.com"
password = "app_password"
use_tls = true
```

### Slack Alerts

```toml
[monitor.alerts.slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

Get webhook URL from: https://api.slack.com/messaging/webhooks

### Microsoft Teams Alerts

```toml
[monitor.alerts.teams]
enabled = true
webhook_url = "https://outlook.office.com/webhook/..."
```

Create webhook: Teams → Channel → Connectors → Incoming Webhook

### PagerDuty Alerts

```toml
[monitor.alerts.pagerduty]
enabled = true
integration_key = "your_integration_key"
```

Get integration key from: PagerDuty → Services → Integrations → Events API v2

### Generic Webhooks

```toml
[monitor.alerts.webhook]
enabled = true
url = "https://your-endpoint.com/alerts"

[monitor.alerts.webhook.headers]
Authorization = "Bearer token"
```

## Domain List Format

```text
# Comments start with #
# Format: hostname[:port] [interval]

# Production servers (default 1h interval)
example.com
api.example.com

# Custom port and interval
internal.corp.com:8443 30m

# Supported intervals
fast-server.com 30s     # 30 seconds
medium-server.com 15m   # 15 minutes
slow-server.com 6h      # 6 hours
daily-server.com 1d     # 1 day
```

## Change Detection

The monitor detects and alerts on:

### Certificate Changes

- **Renewal** (Info): Same issuer, new serial number
- **Issuer Change** (Critical): Different CA - possible security issue
- **Key Size Change** (High): Public key size changed
- **Signature Algorithm Change** (Medium): Different signing algorithm
- **SAN Change** (Medium): Subject Alternative Names modified
- **Expiry Extended** (Low): Certificate validity period extended
- **Expiry Shortened** (Medium): Certificate validity period reduced

### Severity Levels

- **Critical**: Immediate action required (issuer change)
- **High**: Important changes (key size, immediate expiry)
- **Medium**: Notable changes (SAN, signature algorithm)
- **Low**: Routine changes (expiry extended)
- **Info**: Normal operations (renewal)

## Deployment

### Systemd Service

```bash
# Install service
sudo cp examples/cipherrun-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload

# Start service
sudo systemctl start cipherrun-monitor

# Enable on boot
sudo systemctl enable cipherrun-monitor

# View logs
sudo journalctl -u cipherrun-monitor -f
```

### Docker Compose

```bash
# Start with Docker Compose
cd examples
docker-compose -f docker-compose.monitor.yml up -d

# View logs
docker-compose -f docker-compose.monitor.yml logs -f monitor

# Stop
docker-compose -f docker-compose.monitor.yml down
```

### Kubernetes

Example deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cipherrun-monitor
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cipherrun-monitor
  template:
    metadata:
      labels:
        app: cipherrun-monitor
    spec:
      containers:
      - name: monitor
        image: cipherrun:latest
        args:
          - "monitor"
          - "--config"
          - "/etc/cipherrun/monitor.toml"
          - "--domains"
          - "/etc/cipherrun/domains.txt"
        volumeMounts:
          - name: config
            mountPath: /etc/cipherrun
            readOnly: true
      volumes:
        - name: config
          configMap:
            name: cipherrun-config
```

## Database Integration

### PostgreSQL Setup

```sql
CREATE DATABASE cipherrun;
CREATE USER cipherrun_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE cipherrun TO cipherrun_user;
```

Update `monitor.toml`:
```toml
database_url = "postgres://cipherrun_user:secure_password@localhost/cipherrun"
```

### SQLite Setup

```toml
database_url = "sqlite:///var/lib/cipherrun/monitor.db"
```

## Alert Deduplication

Prevents alert spam by not sending duplicate alerts within a time window:

```toml
[monitor.deduplication]
window_hours = 24  # Don't repeat same alert within 24 hours
```

## Monitoring the Monitor

### Health Checks

```bash
# Check daemon status
cipherrun monitor --status

# View statistics
cipherrun monitor --stats
```

### Metrics

The daemon exposes metrics for:
- Total domains monitored
- Successful/failed scans
- Alert delivery status
- Scan duration percentiles

## Security Best Practices

1. **Credentials**: Store passwords in environment variables or secrets manager
2. **TLS**: Always use TLS for SMTP (use_tls = true)
3. **Firewall**: Restrict outbound connections to necessary services
4. **Least Privilege**: Run as dedicated user (not root)
5. **Monitoring**: Monitor the monitor daemon itself (health checks)
6. **Backup**: Backup configuration and domain lists regularly
7. **Rotation**: Rotate API keys and passwords periodically

## Troubleshooting

### Email Not Sending

```bash
# Test SMTP connection
cipherrun monitor --test-alerts --config monitor.toml

# Check firewall
telnet smtp.gmail.com 587

# Verify credentials
# For Gmail: Use App Passwords, not account password
```

### Slack Webhook Failing

```bash
# Test webhook manually
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test"}' \
  https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Check webhook URL is correct
# Verify webhook is enabled in Slack workspace
```

### High CPU Usage

```bash
# Reduce concurrent scans
max_concurrent_scans = 5

# Increase scan intervals
default_interval_seconds = 7200  # 2 hours
```

### Database Connection Issues

```bash
# Test connection
psql "postgres://user:pass@localhost/cipherrun"

# Check PostgreSQL is running
sudo systemctl status postgresql

# Verify network connectivity
telnet localhost 5432
```

## Advanced Usage

### Custom Alert Logic

Implement custom `AlertChannel`:

```rust
use cipherrun::monitor::alerts::{Alert, AlertChannel};
use async_trait::async_trait;

pub struct CustomChannel {
    // Your fields
}

#[async_trait]
impl AlertChannel for CustomChannel {
    async fn send_alert(&self, alert: &Alert) -> Result<()> {
        // Your custom logic
        Ok(())
    }

    fn channel_name(&self) -> &str {
        "custom"
    }
}
```

### Programmatic Usage

```rust
use cipherrun::monitor::{MonitorDaemon, MonitorConfig};

#[tokio::main]
async fn main() -> Result<()> {
    let config = MonitorConfig::from_file("monitor.toml")?;
    let daemon = MonitorDaemon::new(config).await?;

    daemon.load_domains("domains.txt").await?;
    daemon.start().await?;

    Ok(())
}
```

## Performance Tuning

### Optimal Settings

For **1000 domains**:
```toml
max_concurrent_scans = 50
default_interval_seconds = 3600  # 1 hour
```

For **100 domains**:
```toml
max_concurrent_scans = 10
default_interval_seconds = 1800  # 30 minutes
```

### Resource Usage

Typical resource usage:
- Memory: ~50MB base + ~1MB per 100 domains
- CPU: ~5% average (spikes during scans)
- Network: ~10KB per domain scan

## Support

- Issues: https://github.com/seifreed/cipherrun/issues
- Discussions: https://github.com/seifreed/cipherrun/discussions
- Documentation: https://docs.rs/cipherrun

## License

GPL-3.0 - See LICENSE file for details
