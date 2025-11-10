#!/usr/bin/env python3
"""WebSocket real-time progress monitoring example.

This example demonstrates how to:
1. Create a scan using the sync client
2. Monitor progress in real-time using WebSocket
3. Display a progress bar and stage updates
"""

import asyncio
import sys
from datetime import datetime
from cipherrun import CipherRunClient, WebSocketProgressClient, ScanOptions, ProgressMessage


def print_progress_bar(progress: int, width: int = 50):
    """Print a text-based progress bar.

    Args:
        progress: Progress percentage (0-100)
        width: Width of the progress bar in characters
    """
    filled = int(width * progress / 100)
    bar = "=" * filled + "-" * (width - filled)
    print(f"\r[{bar}] {progress}%", end="", flush=True)


async def monitor_scan_progress(scan_id: str):
    """Monitor scan progress via WebSocket.

    Args:
        scan_id: ID of the scan to monitor
    """
    print(f"\nMonitoring scan {scan_id} via WebSocket...\n")

    start_time = datetime.now()
    last_stage = None

    async with WebSocketProgressClient() as ws_client:
        try:
            async for progress in ws_client.stream_progress(scan_id):
                # Display stage changes
                if progress.stage != last_stage:
                    if last_stage is not None:
                        print()  # New line after progress bar
                    print(f"\n[{progress.timestamp.strftime('%H:%M:%S')}] Stage: {progress.stage}")
                    if progress.details:
                        print(f"  {progress.details}")
                    last_stage = progress.stage

                # Update progress bar
                print_progress_bar(progress.progress)

                # Handle completion
                if progress.msg_type == "completed":
                    print()  # New line after final progress bar
                    elapsed = (datetime.now() - start_time).total_seconds()
                    print(f"\nScan completed in {elapsed:.1f} seconds!")
                    break

                elif progress.msg_type == "failed":
                    print()
                    print(f"\nScan failed: {progress.details}")
                    sys.exit(1)

                elif progress.msg_type == "cancelled":
                    print()
                    print("\nScan was cancelled")
                    sys.exit(1)

        except KeyboardInterrupt:
            print("\n\nMonitoring interrupted by user")
            raise


async def handle_progress_callback(progress: ProgressMessage):
    """Callback function to handle progress updates.

    Args:
        progress: Progress message from WebSocket
    """
    timestamp = progress.timestamp.strftime("%H:%M:%S")
    print(f"[{timestamp}] {progress.stage}: {progress.progress}%")
    if progress.details:
        print(f"  Details: {progress.details}")


async def monitor_with_callback(scan_id: str):
    """Monitor scan using callback function.

    Args:
        scan_id: ID of the scan to monitor
    """
    print(f"\nMonitoring scan {scan_id} with callback...\n")

    async with WebSocketProgressClient() as ws_client:
        await ws_client.stream_progress_with_callback(
            scan_id=scan_id,
            callback=handle_progress_callback,
        )


def main():
    # Initialize sync client to create scan
    client = CipherRunClient()

    try:
        # Get target from command line or use default
        target = sys.argv[1] if len(sys.argv) > 1 else "example.com:443"

        print(f"Creating scan for {target}...")
        scan = client.create_scan(target, ScanOptions.full())
        print(f"Scan created: {scan.scan_id}")

        # Choose monitoring method
        use_callback = "--callback" in sys.argv

        if use_callback:
            asyncio.run(monitor_with_callback(scan.scan_id))
        else:
            asyncio.run(monitor_scan_progress(scan.scan_id))

        # Get final results
        print("\nRetrieving final results...")
        results = client.get_scan_results(scan.scan_id)

        # Display summary
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {results.target}")

        if results.rating:
            print(f"Grade: {results.rating.grade} ({results.rating.score}/100)")

        protocols_supported = sum(1 for p in results.protocols if p.supported)
        print(f"Protocols: {protocols_supported}/{len(results.protocols)} supported")

        vulnerabilities = sum(1 for v in results.vulnerabilities if v.vulnerable)
        if vulnerabilities > 0:
            print(f"Vulnerabilities: {vulnerabilities} FOUND")
        else:
            print("Vulnerabilities: None detected")

        print(f"Total Time: {results.scan_time_ms}ms")
        print("=" * 60)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        try:
            client.cancel_scan(scan.scan_id)
            print("Scan cancelled")
        except:
            pass
        sys.exit(1)

    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)

    finally:
        client.close()


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: python websocket_progress.py [target] [--callback]")
        print()
        print("Arguments:")
        print("  target      Target to scan (default: example.com:443)")
        print("  --callback  Use callback mode instead of progress bar")
        print()
        print("Examples:")
        print("  python websocket_progress.py")
        print("  python websocket_progress.py google.com:443")
        print("  python websocket_progress.py example.com:443 --callback")
        sys.exit(0)

    main()
