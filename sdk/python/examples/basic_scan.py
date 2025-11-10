#!/usr/bin/env python3
"""Basic synchronous scan example.

This example demonstrates how to:
1. Create a basic scan
2. Monitor scan progress
3. Retrieve and display results
"""

import sys
import time
from cipherrun import CipherRunClient, ScanOptions, ScanStatus


def main():
    # Initialize client (no API key required for local development)
    client = CipherRunClient(
        base_url="http://localhost:8080",
        api_key=None,  # Set to your API key if required
    )

    try:
        # Target to scan
        target = "example.com:443"
        print(f"Starting scan of {target}...")

        # Create scan with full options
        scan = client.create_scan(target, ScanOptions.full())
        print(f"Scan created with ID: {scan.scan_id}")
        print(f"Status: {scan.status}")

        if scan.websocket_url:
            print(f"WebSocket URL: {scan.websocket_url}")

        print("\nMonitoring scan progress...")

        # Poll for scan completion
        while True:
            status = client.get_scan_status(scan.scan_id)

            print(f"[{status.progress}%] Status: {status.status}", end="")
            if status.current_stage:
                print(f" - {status.current_stage}", end="")
            if status.eta_seconds:
                print(f" (ETA: {status.eta_seconds}s)", end="")
            print()

            if status.status == ScanStatus.COMPLETED:
                print("\nScan completed successfully!")
                break
            elif status.status == ScanStatus.FAILED:
                print(f"\nScan failed: {status.error}")
                sys.exit(1)
            elif status.status == ScanStatus.CANCELLED:
                print("\nScan was cancelled")
                sys.exit(1)

            time.sleep(2)

        # Get full results
        print("\nRetrieving results...")
        results = client.get_scan_results(scan.scan_id)

        # Display results summary
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"Target: {results.target}")
        print(f"Scan Time: {results.scan_time_ms}ms")

        # Protocols
        print(f"\nProtocols Tested: {len(results.protocols)}")
        for protocol in results.protocols:
            status_str = "Supported" if protocol.supported else "Not Supported"
            print(f"  {protocol.protocol}: {status_str}")

        # Ciphers
        print(f"\nCipher Suites: {len(results.ciphers)} protocols analyzed")
        for protocol_name, cipher_summary in results.ciphers.items():
            print(f"  {protocol_name}: {cipher_summary.counts.total} ciphers")
            print(f"    High Strength: {cipher_summary.counts.high_strength}")
            print(f"    Forward Secrecy: {cipher_summary.counts.forward_secrecy}")

        # Certificate
        if results.certificate_chain:
            cert = results.certificate_chain
            print(f"\nCertificate Chain:")
            print(f"  Length: {cert.chain.chain_length} certificates")
            print(f"  Valid: {cert.validation.valid}")
            print(f"  Hostname Match: {cert.validation.hostname_match}")
            print(f"  Not Expired: {cert.validation.not_expired}")

        # Vulnerabilities
        print(f"\nVulnerabilities: {len(results.vulnerabilities)} checks")
        vulnerable_count = sum(1 for v in results.vulnerabilities if v.vulnerable)
        if vulnerable_count > 0:
            print(f"  VULNERABLE: {vulnerable_count} issues found!")
            for vuln in results.vulnerabilities:
                if vuln.vulnerable:
                    print(f"    [{vuln.severity}] {vuln.vuln_type}: {vuln.details}")
        else:
            print("  No vulnerabilities detected")

        # HTTP Headers
        if results.http_headers:
            print(f"\nHTTP Security Headers:")
            print(f"  Grade: {results.http_headers.grade}")
            print(f"  Score: {results.http_headers.score}/100")
            print(f"  Issues: {len(results.http_headers.issues)}")

        # SSL Labs Rating
        if results.rating:
            print(f"\nSSL Labs Rating:")
            print(f"  Overall Grade: {results.rating.grade}")
            print(f"  Score: {results.rating.score}/100")
            print(f"  Certificate: {results.rating.certificate_score}/100")
            print(f"  Protocol Support: {results.rating.protocol_score}/100")
            print(f"  Key Exchange: {results.rating.key_exchange_score}/100")
            print(f"  Cipher Strength: {results.rating.cipher_strength_score}/100")

            if results.rating.warnings:
                print(f"\n  Warnings:")
                for warning in results.rating.warnings:
                    print(f"    - {warning}")

        print("\n" + "=" * 60)
        print("Scan complete!")

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        try:
            if client.cancel_scan(scan.scan_id):
                print("Scan cancelled successfully")
        except:
            pass
        sys.exit(1)

    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)

    finally:
        client.close()


if __name__ == "__main__":
    main()
