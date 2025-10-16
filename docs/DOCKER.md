# CipherRun Docker Testing Environment

Complete Docker environment with network analysis tools for debugging TLS/SSL connections.

## Features

- **CipherRun** - Built from source in release mode
- **Network Analysis Tools**:
  - `tcpdump` - Packet capture
  - `tshark`/`wireshark-common` - Protocol analysis
  - `nmap` - Network scanning
- **SSL/TLS Tools**:
  - `openssl` - OpenSSL client
  - `sslscan` - SSL/TLS scanner
  - `testssl.sh` - SSL/TLS testing suite
- **Helper Scripts** - Automated testing and comparison

## Quick Start

### Build and Run

```bash
# Build the Docker image
docker-compose build

# Start the container
docker-compose up -d

# Enter the container
docker-compose exec cipherrun bash
```

### Alternative: Direct Docker Commands

```bash
# Build image
docker build -t cipherrun:latest .

# Run container with packet capture capabilities
docker run -it --rm \
  --network host \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v $(pwd)/captures:/captures \
  -v $(pwd)/results:/results \
  cipherrun:latest
```

## Usage

### Basic Testing

Once inside the container:

```bash
# Test a domain
cipherrun google.com

# Run with all options
cipherrun -a google.com
```

### Capture and Test

Capture network traffic while running a scan:

```bash
/scripts/capture-and-test.sh creand.es
```

This will:
1. Start tcpdump packet capture
2. Run CipherRun scan
3. Save PCAP file to `/captures/`
4. Save results to `/results/`
5. Show basic analysis

### Compare ClientHello Packets

Compare ClientHello from OpenSSL vs CipherRun:

```bash
/scripts/compare-clienthello.sh creand.es
```

This will:
1. Capture OpenSSL ClientHello (working)
2. Capture CipherRun ClientHello (may fail on strict servers)
3. Extract and compare TLS extensions
4. Highlight differences

### Batch Testing

Test multiple domains at once:

```bash
/scripts/batch-test.sh
```

Results saved to `/results/batch_test_YYYYMMDD_HHMMSS.csv`

### Manual Analysis

#### Analyze PCAP Files

```bash
# List captured packets
tshark -r /captures/domain_timestamp.pcap

# Filter TLS handshakes only
tshark -r /captures/domain_timestamp.pcap -Y 'tls.handshake.type == 1'

# Extract ClientHello details
tshark -r /captures/domain_timestamp.pcap \
  -Y 'tls.handshake.type == 1' -V

# Export as JSON
tshark -r /captures/domain_timestamp.pcap \
  -Y 'tls.handshake.type == 1' -T json > /results/clienthello.json
```

#### Compare Tools

```bash
# Test with OpenSSL
echo | openssl s_client -connect domain.com:443 -tls1_3

# Test with sslscan
sslscan domain.com

# Test with testssl.sh
testssl.sh domain.com
```

## Directory Structure

```
/cipherrun/          # CipherRun source code
├── target/release/  # Built binary
└── src/             # Source files

/captures/           # PCAP files (persistent)
/results/            # Scan results (persistent)
/scripts/            # Helper scripts
```

## Helper Scripts

### capture-and-test.sh

```bash
/scripts/capture-and-test.sh <domain>
```

Captures packets during scan and provides basic analysis.

### compare-clienthello.sh

```bash
/scripts/compare-clienthello.sh <domain>
```

Compares OpenSSL and CipherRun ClientHello packets side-by-side.

### batch-test.sh

```bash
/scripts/batch-test.sh
```

Tests 18 predefined domains and generates CSV report.

## Troubleshooting

### Permission Issues

If you encounter permission errors with packet capture:

```bash
# Run container with privileged mode
docker run -it --rm --privileged --network host cipherrun:latest
```

### PCAP Files Not Saving

Ensure volumes are mounted correctly:

```bash
# Check mounts
docker inspect cipherrun-testing | grep Mounts -A 10

# Create directories if needed
mkdir -p captures results
chmod 777 captures results
```

### Container Exits Immediately

Use interactive mode:

```bash
docker-compose run --rm cipherrun bash
```

## Examples

### Debug TLS 1.3 Handshake Failure

```bash
# 1. Enter container
docker-compose exec cipherrun bash

# 2. Compare ClientHello with working server (Google) vs failing server (creand.es)
/scripts/compare-clienthello.sh google.com
/scripts/compare-clienthello.sh creand.es

# 3. Analyze differences
cd /captures
tshark -r openssl_google.com_*.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extension.type
tshark -r cipherrun_google.com_*.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extension.type
```

### Batch Test and Generate Report

```bash
# Inside container
/scripts/batch-test.sh

# View results
cat /results/batch_test_*.csv

# Copy to host
exit
docker cp cipherrun-testing:/results/batch_test_*.csv ./results/
```

### Capture Long-Running Test

```bash
# Start capture in background
tcpdump -i any -w /captures/long_test.pcap &
TCPDUMP_PID=$!

# Run multiple scans
for domain in google.com facebook.com twitter.com; do
    cipherrun $domain > /results/${domain}_scan.txt 2>&1
done

# Stop capture
kill $TCPDUMP_PID

# Analyze
tshark -r /captures/long_test.pcap -q -z io,stat,1
```

## Advanced Usage

### Custom Packet Filters

```bash
# Capture only TLS handshakes
tcpdump -i any -w /captures/tls_only.pcap \
  'tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)'

# Capture specific domain
tcpdump -i any -w /captures/specific.pcap \
  'host creand.es and port 443'
```

### Export for Wireshark Analysis

```bash
# Copy PCAP to host for GUI analysis
docker cp cipherrun-testing:/captures/domain.pcap ./

# Open in Wireshark on host
wireshark domain.pcap
```

## Cleanup

```bash
# Stop and remove container
docker-compose down

# Remove image
docker rmi cipherrun:latest

# Clean volumes
rm -rf captures/* results/*
```

## Tips

1. **Always use host network mode** for accurate packet capture
2. **Run with privileged mode** for tcpdump to work properly
3. **Compare working vs failing domains** to identify patterns
4. **Use tshark filters** to focus on relevant packets
5. **Export to JSON** for programmatic analysis

## Common TLS 1.3 Extensions (for reference)

| Code | Extension Name |
|------|---------------|
| 0x0000 | server_name (SNI) |
| 0x000a | supported_groups |
| 0x000b | ec_point_formats |
| 0x000d | signature_algorithms |
| 0x0010 | application_layer_protocol_negotiation |
| 0x0017 | extended_master_secret |
| 0x002b | supported_versions |
| 0x002d | psk_key_exchange_modes |
| 0x0033 | key_share |
| 0x0050 | signature_algorithms_cert |
| 0xff01 | renegotiation_info |

## Support

For issues specific to the Docker environment, check:
- Logs: `docker-compose logs`
- Container status: `docker-compose ps`
- Resource usage: `docker stats cipherrun-testing`
