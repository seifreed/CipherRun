#!/usr/bin/env python3
"""Compliance checking example.

This example demonstrates how to:
1. Check compliance against various frameworks
2. Display compliance status
3. Generate compliance reports
"""

import sys
from cipherrun import CipherRunClient


def check_compliance(client: CipherRunClient, target: str, framework: str):
    """Check compliance for a target against a framework.

    Args:
        client: CipherRun client
        target: Target to check
        framework: Compliance framework

    Returns:
        ComplianceReport
    """
    print(f"\nChecking {framework.upper()} compliance for {target}...")

    try:
        report = client.check_compliance(framework, target, detailed=True)

        print(f"\nFramework: {report.framework}")
        print(f"Status: {report.status}")

        if report.message:
            print(f"Message: {report.message}")

        return report

    except Exception as e:
        print(f"Error checking compliance: {e}")
        return None


def main():
    # Initialize client
    client = CipherRunClient()

    try:
        # Get target from command line or use default
        target = sys.argv[1] if len(sys.argv) > 1 else "example.com:443"

        print("=" * 80)
        print("COMPLIANCE CHECKING")
        print("=" * 80)
        print(f"Target: {target}")

        # Available compliance frameworks
        frameworks = [
            ("pci-dss-v4", "PCI DSS v4.0"),
            ("nist-sp800-52r2", "NIST SP 800-52 Rev. 2"),
            ("fedramp", "FedRAMP"),
            ("hipaa", "HIPAA"),
        ]

        print("\nAvailable Frameworks:")
        for code, name in frameworks:
            print(f"  - {name} ({code})")

        # Check all frameworks or specific one
        if len(sys.argv) > 2:
            # Check specific framework from command line
            framework = sys.argv[2]
            check_compliance(client, target, framework)
        else:
            # Check all frameworks
            print("\nChecking all frameworks...")
            print("-" * 80)

            results = {}
            for code, name in frameworks:
                report = check_compliance(client, target, code)
                if report:
                    results[name] = report

            # Display summary
            print("\n" + "=" * 80)
            print("COMPLIANCE SUMMARY")
            print("=" * 80)

            for name, report in results.items():
                status_symbol = "✓" if report.status == "compliant" else "✗"
                print(f"{status_symbol} {name}: {report.status}")

        print("\n" + "=" * 80)

        # Note about implementation
        print("\nNote: Compliance checking is currently in development.")
        print("Full compliance reports will be available in a future release.")
        print("Current implementation returns framework validation status.")

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)

    finally:
        client.close()


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: python compliance_check.py [target] [framework]")
        print()
        print("Arguments:")
        print("  target      Target to check (default: example.com:443)")
        print("  framework   Specific framework to check (optional)")
        print()
        print("Available frameworks:")
        print("  pci-dss-v4       - PCI DSS v4.0")
        print("  nist-sp800-52r2  - NIST SP 800-52 Rev. 2")
        print("  fedramp          - FedRAMP")
        print("  hipaa            - HIPAA")
        print()
        print("Examples:")
        print("  python compliance_check.py")
        print("  python compliance_check.py example.com:443")
        print("  python compliance_check.py example.com:443 pci-dss-v4")
        sys.exit(0)

    main()
