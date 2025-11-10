#!/usr/bin/env python3
"""Asynchronous batch scanning example.

This example demonstrates how to:
1. Scan multiple targets concurrently using async/await
2. Process results as they complete
3. Generate a summary report
"""

import asyncio
import sys
from typing import List, Tuple
from cipherrun import AsyncCipherRunClient, ScanOptions, ScanResults


async def scan_target(client: AsyncCipherRunClient, target: str) -> Tuple[str, ScanResults]:
    """Scan a single target and return results.

    Args:
        client: Async CipherRun client
        target: Target to scan

    Returns:
        Tuple of (target, results)
    """
    print(f"[{target}] Starting scan...")

    # Create scan with quick options for faster results
    scan = await client.create_scan(target, ScanOptions.quick())
    print(f"[{target}] Scan ID: {scan.scan_id}")

    # Wait for completion
    results = await client.wait_for_scan(scan.scan_id, poll_interval=3)
    print(f"[{target}] Scan completed!")

    return target, results


async def scan_multiple_targets(targets: List[str]):
    """Scan multiple targets concurrently.

    Args:
        targets: List of targets to scan
    """
    print(f"Starting batch scan of {len(targets)} targets...\n")

    async with AsyncCipherRunClient() as client:
        # Create tasks for all targets
        tasks = [scan_target(client, target) for target in targets]

        # Wait for all scans to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        successful = []
        failed = []

        for result in results:
            if isinstance(result, Exception):
                failed.append(str(result))
            else:
                successful.append(result)

        # Display summary
        print("\n" + "=" * 80)
        print("BATCH SCAN RESULTS")
        print("=" * 80)

        print(f"\nTotal Targets: {len(targets)}")
        print(f"Successful: {len(successful)}")
        print(f"Failed: {len(failed)}")

        # Display successful scans
        if successful:
            print("\n" + "-" * 80)
            print("SUCCESSFUL SCANS")
            print("-" * 80)

            for target, scan_results in successful:
                print(f"\n{target}")
                print("-" * len(target))

                # Protocol summary
                supported_protocols = [p.protocol for p in scan_results.protocols if p.supported]
                print(f"Supported Protocols: {', '.join(supported_protocols)}")

                # Certificate info
                if scan_results.certificate_chain:
                    cert = scan_results.certificate_chain
                    status = "Valid" if cert.validation.valid else "Invalid"
                    print(f"Certificate: {status}")

                # Vulnerabilities
                vulnerable = [v for v in scan_results.vulnerabilities if v.vulnerable]
                if vulnerable:
                    print(f"Vulnerabilities: {len(vulnerable)} FOUND")
                    for vuln in vulnerable:
                        print(f"  - [{vuln.severity}] {vuln.vuln_type}")
                else:
                    print("Vulnerabilities: None detected")

                # Rating
                if scan_results.rating:
                    print(f"SSL Labs Grade: {scan_results.rating.grade} ({scan_results.rating.score}/100)")

                print(f"Scan Time: {scan_results.scan_time_ms}ms")

        # Display failures
        if failed:
            print("\n" + "-" * 80)
            print("FAILED SCANS")
            print("-" * 80)
            for error in failed:
                print(f"  - {error}")

        print("\n" + "=" * 80)


async def main():
    # Define targets to scan
    targets = [
        "example.com:443",
        "google.com:443",
        "github.com:443",
        "cloudflare.com:443",
        "amazon.com:443",
    ]

    try:
        await scan_multiple_targets(targets)
    except KeyboardInterrupt:
        print("\n\nBatch scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
