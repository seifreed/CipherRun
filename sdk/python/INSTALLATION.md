# CipherRun Python SDK - Installation Guide

## Quick Installation

### From PyPI (Once Published)

```bash
pip install cipherrun
```

### From Source (Development)

```bash
# Clone the repository
git clone https://github.com/yourusername/cipherrun.git
cd cipherrun/sdk/python

# Install in development mode
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

## Requirements

- Python 3.8 or higher
- pip (Python package installer)

## Dependencies

The SDK requires the following packages:

- `requests>=2.31.0` - HTTP client for synchronous requests
- `aiohttp>=3.9.0` - HTTP client for async requests
- `websockets>=12.0` - WebSocket client for progress streaming
- `pydantic>=2.0.0` - Data validation and type hints

These will be automatically installed when you install the SDK.

## Verification

After installation, verify the SDK is working:

```python
python3 -c "import cipherrun; print(cipherrun.__version__)"
```

You should see: `1.0.0`

## Virtual Environment (Recommended)

It's recommended to use a virtual environment:

```bash
# Create virtual environment
python3 -m venv venv

# Activate it (Linux/macOS)
source venv/bin/activate

# Activate it (Windows)
venv\Scripts\activate

# Install the SDK
pip install cipherrun
```

## Development Installation

For SDK development and testing:

```bash
# Clone and navigate to SDK directory
cd cipherrun/sdk/python

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy cipherrun

# Code formatting
black cipherrun
ruff check cipherrun
```

## Running Examples

After installation, you can run the example scripts:

```bash
# Basic scan
python examples/basic_scan.py example.com:443

# Async batch scanning
python examples/async_scan.py

# WebSocket progress monitoring
python examples/websocket_progress.py example.com:443

# Compliance checking
python examples/compliance_check.py example.com:443

# Policy evaluation
python examples/policy_evaluation.py example.com:443
```

## Building from Source

To build distribution packages:

```bash
# Install build tools
pip install build twine

# Build the package
python -m build

# This creates:
# - dist/cipherrun-1.0.0.tar.gz (source distribution)
# - dist/cipherrun-1.0.0-py3-none-any.whl (wheel)
```

## Publishing to PyPI

For maintainers:

```bash
# Test on TestPyPI first
twine upload --repository testpypi dist/*

# Then publish to PyPI
twine upload dist/*
```

## Troubleshooting

### Import Error

If you get `ModuleNotFoundError: No module named 'cipherrun'`:

1. Ensure you're in the correct virtual environment
2. Reinstall: `pip install -e .`
3. Check installation: `pip list | grep cipherrun`

### Version Conflicts

If you encounter dependency conflicts:

```bash
# Create fresh virtual environment
python3 -m venv fresh-env
source fresh-env/bin/activate
pip install cipherrun
```

### WebSocket Connection Issues

If WebSocket connections fail:

1. Check the CipherRun API is running
2. Verify the base URL is correct
3. Ensure no firewall is blocking WebSocket connections

## Platform-Specific Notes

### macOS

```bash
# May need to install certificates for SSL
/Applications/Python\ 3.x/Install\ Certificates.command
```

### Windows

```bash
# Use py launcher
py -m pip install cipherrun

# Or specify Python version
py -3.8 -m pip install cipherrun
```

### Linux

```bash
# May need python3-dev for some dependencies
sudo apt-get install python3-dev  # Debian/Ubuntu
sudo yum install python3-devel    # RHEL/CentOS
```

## Upgrading

To upgrade to the latest version:

```bash
pip install --upgrade cipherrun
```

## Uninstallation

To remove the SDK:

```bash
pip uninstall cipherrun
```

## Support

For installation issues:
- GitHub Issues: https://github.com/yourusername/cipherrun/issues
- Documentation: https://docs.cipherrun.com
- Email: support@cipherrun.com
