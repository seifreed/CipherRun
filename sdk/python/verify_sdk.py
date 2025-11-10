#!/usr/bin/env python3
"""SDK Verification Script

This script verifies that the CipherRun Python SDK is properly installed
and all components are accessible.
"""

import sys


def verify_imports():
    """Verify all SDK components can be imported."""
    print("Verifying SDK imports...")

    try:
        # Main clients
        from cipherrun import CipherRunClient, AsyncCipherRunClient, WebSocketProgressClient
        print("  ✓ Clients imported successfully")

        # Models
        from cipherrun import (
            ScanOptions, ScanRequest, ScanResponse, ScanStatus,
            ScanStatusResponse, ScanResults, ProgressMessage,
        )
        print("  ✓ Core models imported successfully")

        # Exceptions
        from cipherrun import (
            CipherRunError, BadRequestError, UnauthorizedError,
            RateLimitError, TimeoutError, WebSocketError,
        )
        print("  ✓ Exceptions imported successfully")

        # Version
        from cipherrun import __version__
        print(f"  ✓ SDK version: {__version__}")

        return True

    except ImportError as e:
        print(f"  ✗ Import error: {e}")
        return False


def verify_models():
    """Verify Pydantic models work correctly."""
    print("\nVerifying Pydantic models...")

    try:
        from cipherrun import ScanOptions, ScanRequest

        # Test ScanOptions
        options = ScanOptions.full()
        assert options.test_protocols == True
        assert options.test_ciphers == True
        print("  ✓ ScanOptions.full() works")

        options = ScanOptions.quick()
        assert options.test_protocols == True
        assert options.test_ciphers == False
        print("  ✓ ScanOptions.quick() works")

        # Test ScanRequest
        request = ScanRequest(
            target="example.com:443",
            options=ScanOptions(),
        )
        assert request.target == "example.com:443"
        print("  ✓ ScanRequest validation works")

        return True

    except Exception as e:
        print(f"  ✗ Model error: {e}")
        return False


def verify_client_creation():
    """Verify clients can be instantiated."""
    print("\nVerifying client creation...")

    try:
        from cipherrun import CipherRunClient, AsyncCipherRunClient, WebSocketProgressClient

        # Sync client
        client = CipherRunClient()
        assert client.base_url == "http://localhost:8080"
        client.close()
        print("  ✓ CipherRunClient created successfully")

        # Async client
        async_client = AsyncCipherRunClient()
        assert async_client.base_url == "http://localhost:8080"
        print("  ✓ AsyncCipherRunClient created successfully")

        # WebSocket client
        ws_client = WebSocketProgressClient()
        assert ws_client.base_url == "http://localhost:8080"
        print("  ✓ WebSocketProgressClient created successfully")

        return True

    except Exception as e:
        print(f"  ✗ Client creation error: {e}")
        return False


def verify_context_managers():
    """Verify context manager support."""
    print("\nVerifying context managers...")

    try:
        from cipherrun import CipherRunClient

        # Test sync client context manager
        with CipherRunClient() as client:
            assert client.base_url == "http://localhost:8080"
        print("  ✓ Sync client context manager works")

        return True

    except Exception as e:
        print(f"  ✗ Context manager error: {e}")
        return False


def verify_exceptions():
    """Verify exception hierarchy."""
    print("\nVerifying exceptions...")

    try:
        from cipherrun import (
            CipherRunError, BadRequestError, UnauthorizedError,
            RateLimitError, handle_http_error
        )

        # Test exception creation
        error = BadRequestError("Test error")
        assert error.status_code == 400
        assert "400" in str(error)
        print("  ✓ BadRequestError works")

        # Test rate limit error with retry_after
        rate_error = RateLimitError("Rate limited", retry_after=30)
        assert rate_error.retry_after == 30
        assert "30s" in str(rate_error)
        print("  ✓ RateLimitError with retry_after works")

        # Test error handler
        error = handle_http_error(404, {"message": "Not found"})
        assert error.status_code == 404
        print("  ✓ Error handler works")

        return True

    except Exception as e:
        print(f"  ✗ Exception error: {e}")
        return False


def verify_type_hints():
    """Verify type hints are accessible."""
    print("\nVerifying type hints...")

    try:
        from cipherrun.client import CipherRunClient
        import inspect

        # Get create_scan signature
        sig = inspect.signature(CipherRunClient.create_scan)
        params = sig.parameters

        assert 'target' in params
        assert 'options' in params
        print("  ✓ Type hints are accessible")

        return True

    except Exception as e:
        print(f"  ✗ Type hints error: {e}")
        return False


def main():
    """Run all verification checks."""
    print("=" * 60)
    print("CipherRun Python SDK Verification")
    print("=" * 60)

    checks = [
        ("Imports", verify_imports),
        ("Models", verify_models),
        ("Client Creation", verify_client_creation),
        ("Context Managers", verify_context_managers),
        ("Exceptions", verify_exceptions),
        ("Type Hints", verify_type_hints),
    ]

    results = []
    for name, check_fn in checks:
        try:
            result = check_fn()
            results.append((name, result))
        except Exception as e:
            print(f"\nUnexpected error in {name}: {e}")
            results.append((name, False))

    # Summary
    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} - {name}")

    print(f"\nResults: {passed}/{total} checks passed")

    if passed == total:
        print("\n✓ SDK verification successful!")
        print("All components are working correctly.")
        return 0
    else:
        print("\n✗ SDK verification failed!")
        print("Some components are not working correctly.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
