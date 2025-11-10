"""Setup configuration for CipherRun Python SDK."""

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="cipherrun",
    version="1.0.0",
    description="Official Python SDK for the CipherRun SSL/TLS security scanning API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="CipherRun Team",
    author_email="info@cipherrun.com",
    url="https://github.com/yourusername/cipherrun",
    project_urls={
        "Documentation": "https://docs.cipherrun.com",
        "Source": "https://github.com/yourusername/cipherrun",
        "Tracker": "https://github.com/yourusername/cipherrun/issues",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "websockets>=12.0",
        "pydantic>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "mypy>=1.5.0",
            "ruff>=0.1.0",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed",
    ],
    keywords="ssl tls security scanning api sdk certificate vulnerability compliance",
    license="MIT",
    include_package_data=True,
    zip_safe=False,
)
