# CipherRun REST API Documentation

## Overview

CipherRun provides a production-ready REST API server with WebSocket support for real-time scan progress, background job processing, authentication, rate limiting, and OpenAPI documentation.

## Features

- **Asynchronous Scan Processing**: Queue scans and retrieve results when complete
- **WebSocket Progress Streaming**: Real-time scan progress updates
- **Background Job Queue**: Efficient concurrent scan execution
- **API Key Authentication**: Secure access control with permission levels
- **Rate Limiting**: 100 requests/minute per API key
- **OpenAPI/Swagger Documentation**: Interactive API documentation
- **Comprehensive Error Handling**: Structured error responses
- **CORS Support**: Cross-origin resource sharing enabled

## Quick Start

### Starting the API Server

```bash
# Start with default settings (localhost:8080)
cipherrun --serve

# Start with custom host and port
cipherrun --serve --api-host 0.0.0.0 --api-port 3000

# Start with Swagger UI enabled
cipherrun --serve --api-swagger

# Start with configuration file
cipherrun --serve --api-config api-config.toml

# Generate example configuration
cipherrun --api-config-example api-config.toml
```

### Configuration File

```toml
# api-config.toml
host = "0.0.0.0"
port = 8080
max_concurrent_scans = 10
enable_cors = true
rate_limit_per_minute = 100
max_body_size = 1048576  # 1MB
request_timeout_seconds = 300
ws_ping_interval_seconds = 30
job_queue_capacity = 1000
enable_swagger = true

[api_keys]
"demo-key-12345" = "User"
"admin-key-67890" = "Admin"
"readonly-key-abc" = "ReadOnly"
```

## Authentication

All endpoints (except `/health`) require authentication via API key.

### Header

```http
X-API-Key: your-api-key-here
```

### Permission Levels

- **Admin**: Full access (create, read, update, delete)
- **User**: Can create and read scans
- **ReadOnly**: Can only read existing data

## API Endpoints

### Health Check

```http
GET /api/v1/health
```

Returns service health status (no authentication required).

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "active_scans": 2,
  "queued_scans": 5,
  "database": "connected"
}
```

### Create Scan

```http
POST /api/v1/scan
Content-Type: application/json
X-API-Key: your-key
```

**Request Body:**
```json
{
  "target": "example.com:443",
  "options": {
    "test_protocols": true,
    "test_ciphers": true,
    "test_vulnerabilities": true,
    "analyze_certificates": true,
    "test_http_headers": true,
    "client_simulation": false,
    "timeout_seconds": 30,
    "full_scan": false
  },
  "webhook_url": "https://your-app.com/webhook"
}
```

**Response (201 Created):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "target": "example.com:443",
  "websocket_url": "/api/v1/scan/550e8400-e29b-41d4-a716-446655440000/stream",
  "queued_at": "2025-11-09T12:00:00Z"
}
```

### Get Scan Status

```http
GET /api/v1/scan/{id}
X-API-Key: your-key
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "progress": 45,
  "current_stage": "testing_ciphers",
  "eta_seconds": 120,
  "started_at": "2025-11-09T12:00:30Z"
}
```

Status values: `queued`, `running`, `completed`, `failed`, `cancelled`

### Get Scan Results

```http
GET /api/v1/scan/{id}/results
X-API-Key: your-key
```

**Response:**
```json
{
  "target": "example.com:443",
  "scan_time_ms": 15234,
  "protocols": { ... },
  "ciphers": { ... },
  "certificate_chain": { ... },
  "vulnerabilities": { ... },
  "rating": {
    "overall_grade": "A",
    "score": 95
  }
}
```

### Cancel Scan

```http
DELETE /api/v1/scan/{id}
X-API-Key: your-key
```

**Response:**
```json
{
  "message": "Scan cancelled successfully",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### WebSocket Progress Stream

```
WS /api/v1/scan/{id}/stream
```

Connect to receive real-time progress updates:

```javascript
const ws = new WebSocket('ws://localhost:8080/api/v1/scan/{id}/stream');

ws.onmessage = (event) => {
  const progress = JSON.parse(event.data);
  console.log(`Progress: ${progress.progress}% - ${progress.stage}`);
};
```

**Message Format:**
```json
{
  "msg_type": "progress",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "progress": 45,
  "stage": "testing_ciphers",
  "details": "Testing TLS 1.2 cipher suites",
  "timestamp": "2025-11-09T12:00:45Z"
}
```

### List Certificates

```http
GET /api/v1/certificates?limit=50&offset=0&sort=expiry_asc
X-API-Key: your-key
```

**Response:**
```json
{
  "total": 150,
  "offset": 0,
  "limit": 50,
  "certificates": [
    {
      "fingerprint": "sha256:abcd1234...",
      "common_name": "example.com",
      "san": ["example.com", "*.example.com"],
      "issuer": "Let's Encrypt Authority X3",
      "valid_from": "2025-01-01T00:00:00Z",
      "valid_until": "2025-04-01T00:00:00Z",
      "days_until_expiry": 45,
      "is_expired": false,
      "is_expiring_soon": false,
      "hostnames": ["example.com:443"]
    }
  ]
}
```

### Check Compliance

```http
GET /api/v1/compliance/{framework}?target=example.com:443
X-API-Key: your-key
```

Supported frameworks:
- `pci-dss-v4`
- `nist-sp800-52r2`
- `fedramp`
- `hipaa`

**Response:**
```json
{
  "framework": "pci-dss-v4",
  "target": "example.com:443",
  "compliant": false,
  "checks": [
    {
      "requirement": "Disable SSLv2/SSLv3",
      "passed": true,
      "severity": "critical"
    },
    {
      "requirement": "Require TLS 1.2+",
      "passed": false,
      "severity": "high",
      "message": "TLS 1.0 is enabled"
    }
  ]
}
```

### Scan History

```http
GET /api/v1/history/{domain}?port=443&limit=10
X-API-Key: your-key
```

**Response:**
```json
{
  "domain": "example.com",
  "port": 443,
  "total_scans": 25,
  "scans": [
    {
      "scan_id": "...",
      "timestamp": "2025-11-09T12:00:00Z",
      "grade": "A",
      "score": 95,
      "duration_ms": 12345,
      "vulnerability_count": 0,
      "results_url": "/api/v1/scan/.../results"
    }
  ]
}
```

### API Statistics

```http
GET /api/v1/stats
X-API-Key: your-key
```

**Response:**
```json
{
  "total_scans": 1234,
  "completed_scans": 1200,
  "failed_scans": 34,
  "avg_scan_duration_seconds": 15.3,
  "scans_last_24h": 156,
  "scans_last_7d": 890,
  "top_domains": [
    {
      "domain": "example.com",
      "scan_count": 45,
      "last_scan": "2025-11-09T12:00:00Z"
    }
  ],
  "api_usage": {
    "requests_last_hour": 234,
    "requests_last_day": 5678,
    "avg_response_time_ms": 123.4
  }
}
```

## Error Responses

All errors follow this format:

```json
{
  "status": 400,
  "error": "BAD_REQUEST",
  "message": "Target cannot be empty",
  "details": "..."
}
```

### Error Codes

- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `429` - Rate Limited
- `500` - Internal Server Error
- `503` - Service Unavailable

## Rate Limiting

API requests are limited to 100 requests per minute per API key.

**Rate limit headers:**
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1699545600
```

## Webhooks

Configure webhooks to receive notifications when scans complete:

```json
{
  "target": "example.com:443",
  "webhook_url": "https://your-app.com/webhook"
}
```

**Webhook Payload:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "example.com:443",
  "status": "completed",
  "completed_at": "2025-11-09T12:05:00Z",
  "error": null
}
```

## OpenAPI Documentation

Interactive API documentation is available at:

```
http://localhost:8080/api/docs
```

## Examples

### cURL

```bash
# Create scan
curl -X POST http://localhost:8080/api/v1/scan \
  -H "X-API-Key: demo-key-12345" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com:443",
    "options": {
      "full_scan": true
    }
  }'

# Get scan status
curl http://localhost:8080/api/v1/scan/{id} \
  -H "X-API-Key: demo-key-12345"

# Get results
curl http://localhost:8080/api/v1/scan/{id}/results \
  -H "X-API-Key: demo-key-12345"
```

### Python

```python
import requests
import time

API_KEY = "demo-key-12345"
BASE_URL = "http://localhost:8080/api/v1"

headers = {"X-API-Key": API_KEY}

# Create scan
response = requests.post(
    f"{BASE_URL}/scan",
    headers=headers,
    json={
        "target": "example.com:443",
        "options": {"full_scan": True}
    }
)

scan = response.json()
scan_id = scan["scan_id"]

# Poll for completion
while True:
    status = requests.get(
        f"{BASE_URL}/scan/{scan_id}",
        headers=headers
    ).json()

    print(f"Progress: {status['progress']}%")

    if status["status"] in ["completed", "failed"]:
        break

    time.sleep(2)

# Get results
results = requests.get(
    f"{BASE_URL}/scan/{scan_id}/results",
    headers=headers
).json()

print(f"Grade: {results['rating']['overall_grade']}")
```

### JavaScript/Node.js

```javascript
const axios = require('axios');
const WebSocket = require('ws');

const API_KEY = 'demo-key-12345';
const BASE_URL = 'http://localhost:8080/api/v1';

const headers = {
  'X-API-Key': API_KEY
};

// Create scan
const createScan = async () => {
  const response = await axios.post(
    `${BASE_URL}/scan`,
    {
      target: 'example.com:443',
      options: { full_scan: true }
    },
    { headers }
  );

  return response.data;
};

// Stream progress via WebSocket
const streamProgress = (scanId) => {
  const ws = new WebSocket(
    `ws://localhost:8080/api/v1/scan/${scanId}/stream`
  );

  ws.on('message', (data) => {
    const progress = JSON.parse(data);
    console.log(`${progress.progress}% - ${progress.stage}`);

    if (progress.msg_type === 'completed') {
      ws.close();
    }
  });
};

// Main
(async () => {
  const scan = await createScan();
  console.log(`Scan created: ${scan.scan_id}`);

  streamProgress(scan.scan_id);
})();
```

## Production Deployment

### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/target/release/cipherrun /usr/local/bin/
EXPOSE 8080
CMD ["cipherrun", "--serve", "--api-swagger"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  cipherrun-api:
    build: .
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=info
    volumes:
      - ./api-config.toml:/etc/cipherrun/api-config.toml
    command: >
      cipherrun --serve
      --api-config /etc/cipherrun/api-config.toml
      --api-swagger
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cipherrun-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cipherrun-api
  template:
    metadata:
      labels:
        app: cipherrun-api
    spec:
      containers:
      - name: cipherrun
        image: cipherrun:latest
        ports:
        - containerPort: 8080
        env:
        - name: RUST_LOG
          value: "info"
        args:
        - "--serve"
        - "--api-swagger"
---
apiVersion: v1
kind: Service
metadata:
  name: cipherrun-api
spec:
  selector:
    app: cipherrun-api
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

## Best Practices

1. **Use HTTPS in production** - Deploy behind a reverse proxy with TLS
2. **Rotate API keys regularly** - Implement key rotation policies
3. **Monitor rate limits** - Track API usage and adjust limits as needed
4. **Use webhooks** - Avoid polling by configuring webhooks
5. **Cache results** - Cache completed scan results to reduce API calls
6. **Handle errors gracefully** - Implement retry logic with exponential backoff
7. **Set appropriate timeouts** - Configure client timeouts based on scan complexity

## Support

For issues and questions:
- GitHub: https://github.com/seifreed/cipherrun
- Documentation: https://cipherrun.io/docs
- Email: support@cipherrun.io
