#!/usr/bin/env python3
"""Policy-based security evaluation example.

This example demonstrates how to:
1. Create custom security policies
2. Evaluate targets against policies
3. Display policy violations
"""

import sys
from cipherrun import CipherRunClient, ScanOptions


# Example policy rules in YAML format
EXAMPLE_POLICY = """
# Minimum TLS version policy
min_tls_version: "1.2"

# Allowed cipher suites
allowed_ciphers:
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

# Certificate requirements
certificate:
  min_key_size: 2048
  max_validity_days: 398
  require_san: true

# Security headers
security_headers:
  - Strict-Transport-Security
  - X-Content-Type-Options
  - X-Frame-Options
"""


STRICT_POLICY = """
# Strict security policy
min_tls_version: "1.3"

# Only TLS 1.3 ciphers
allowed_ciphers:
  - TLS_AES_256_GCM_SHA384
  - TLS_AES_128_GCM_SHA256
  - TLS_CHACHA20_POLY1305_SHA256

# Strict certificate requirements
certificate:
  min_key_size: 4096
  max_validity_days: 90
  require_san: true
  require_ocsp_stapling: true

# Required security headers
security_headers:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Content-Type-Options
  - X-Frame-Options
  - Referrer-Policy
  - Permissions-Policy

# Vulnerability checks
vulnerabilities:
  allow_none: true
  max_severity: "low"
"""


def create_policy(client: CipherRunClient, name: str, rules: str) -> str:
    """Create a security policy.

    Args:
        client: CipherRun client
        name: Policy name
        rules: Policy rules in YAML format

    Returns:
        Policy ID
    """
    print(f"\nCreating policy: {name}")

    try:
        policy = client.create_policy(
            name=name,
            description=f"Example policy: {name}",
            rules=rules,
            enabled=True,
        )

        print(f"Policy created with ID: {policy.id}")
        return policy.id

    except Exception as e:
        print(f"Note: Policy creation is currently in development.")
        print(f"Error: {e}")
        return None


def evaluate_policy(client: CipherRunClient, policy_id: str, target: str):
    """Evaluate a target against a policy.

    Args:
        client: CipherRun client
        policy_id: Policy ID
        target: Target to evaluate
    """
    print(f"\nEvaluating {target} against policy...")

    try:
        result = client.evaluate_policy(
            policy_id=policy_id,
            target=target,
            options=ScanOptions.full(),
        )

        print("\n" + "=" * 80)
        print("POLICY EVALUATION RESULTS")
        print("=" * 80)

        print(f"\nPolicy: {result.policy_name}")
        print(f"Target: {result.target}")
        print(f"Scan ID: {result.scan_id}")
        print(f"Evaluated At: {result.evaluated_at}")

        # Overall compliance
        status = "COMPLIANT" if result.compliant else "NON-COMPLIANT"
        symbol = "✓" if result.compliant else "✗"
        print(f"\nOverall Status: {symbol} {status}")

        # Individual checks
        print(f"\nCheck Results: ({len(result.checks)} checks)")
        print("-" * 80)

        passed_checks = [c for c in result.checks if c.passed]
        failed_checks = [c for c in result.checks if not c.passed]

        if failed_checks:
            print(f"\nFailed Checks: {len(failed_checks)}")
            for check in failed_checks:
                print(f"\n  ✗ {check.check}")
                print(f"    Severity: {check.severity}")
                if check.message:
                    print(f"    Message: {check.message}")
                if check.expected and check.actual:
                    print(f"    Expected: {check.expected}")
                    print(f"    Actual: {check.actual}")

        if passed_checks:
            print(f"\nPassed Checks: {len(passed_checks)}")
            for check in passed_checks:
                print(f"  ✓ {check.check}")

        print("\n" + "=" * 80)

    except Exception as e:
        print(f"\nNote: Policy evaluation is currently in development.")
        print(f"Error: {e}")


def demonstrate_scan_based_evaluation(client: CipherRunClient, target: str):
    """Demonstrate manual policy evaluation using scan results.

    Args:
        client: CipherRun client
        target: Target to evaluate
    """
    print(f"\nPerforming manual policy evaluation for {target}...")
    print("(This demonstrates how to evaluate scan results against custom rules)")

    # Create and wait for scan
    scan = client.create_scan(target, ScanOptions.full())
    print(f"Scan created: {scan.scan_id}")

    results = client.wait_for_scan(scan.scan_id, poll_interval=3)

    print("\n" + "=" * 80)
    print("MANUAL POLICY EVALUATION")
    print("=" * 80)

    # Check TLS version support
    print("\nTLS Version Policy:")
    print("  Requirement: TLS 1.2 or higher only")

    tls12_or_higher = [
        p for p in results.protocols
        if p.supported and p.protocol in ["TLS 1.2", "TLS 1.3"]
    ]
    legacy_protocols = [
        p for p in results.protocols
        if p.supported and p.protocol not in ["TLS 1.2", "TLS 1.3"]
    ]

    if legacy_protocols:
        print(f"  ✗ FAIL: Legacy protocols detected:")
        for p in legacy_protocols:
            print(f"    - {p.protocol}")
    else:
        print(f"  ✓ PASS: Only TLS 1.2+ supported")

    # Check certificate
    print("\nCertificate Policy:")
    print("  Requirement: 2048-bit key minimum, valid certificate")

    if results.certificate_chain:
        cert = results.certificate_chain
        if cert.validation.valid:
            print(f"  ✓ PASS: Certificate is valid")
        else:
            print(f"  ✗ FAIL: Certificate validation issues")
            for issue in cert.validation.issues:
                print(f"    - {issue.description}")

    # Check vulnerabilities
    print("\nVulnerability Policy:")
    print("  Requirement: No high or critical vulnerabilities")

    critical_vulns = [
        v for v in results.vulnerabilities
        if v.vulnerable and v.severity.value in ["critical", "high"]
    ]

    if critical_vulns:
        print(f"  ✗ FAIL: {len(critical_vulns)} critical/high vulnerabilities found:")
        for v in critical_vulns:
            print(f"    - [{v.severity.value}] {v.vuln_type}")
    else:
        print(f"  ✓ PASS: No critical/high vulnerabilities")

    # Overall assessment
    print("\n" + "=" * 80)
    all_passed = not legacy_protocols and not critical_vulns
    if results.certificate_chain:
        all_passed = all_passed and results.certificate_chain.validation.valid

    if all_passed:
        print("Overall: ✓ COMPLIANT")
    else:
        print("Overall: ✗ NON-COMPLIANT")

    print("=" * 80)


def main():
    client = CipherRunClient()

    try:
        target = sys.argv[1] if len(sys.argv) > 1 else "example.com:443"

        print("=" * 80)
        print("POLICY-BASED EVALUATION")
        print("=" * 80)
        print(f"Target: {target}")

        # Try to create policies (will fail if not implemented)
        print("\nAttempting to create example policies...")

        policy_id = create_policy(client, "Standard Security Policy", EXAMPLE_POLICY)

        if policy_id:
            # Evaluate against policy
            evaluate_policy(client, policy_id, target)
        else:
            # Fall back to manual evaluation
            print("\nFalling back to manual policy evaluation...")
            demonstrate_scan_based_evaluation(client, target)

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
        print("Usage: python policy_evaluation.py [target]")
        print()
        print("Arguments:")
        print("  target  Target to evaluate (default: example.com:443)")
        print()
        print("This example demonstrates:")
        print("  - Creating custom security policies")
        print("  - Evaluating targets against policies")
        print("  - Manual policy evaluation using scan results")
        print()
        print("Examples:")
        print("  python policy_evaluation.py")
        print("  python policy_evaluation.py google.com:443")
        sys.exit(0)

    main()
