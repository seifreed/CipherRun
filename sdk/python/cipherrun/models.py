"""CipherRun SDK data models.

This module contains Pydantic models for all API requests and responses.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict


# Enums

class ScanStatus(str, Enum):
    """Scan status enumeration."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    """Severity level enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityGrade(str, Enum):
    """Security grade enumeration."""
    A_PLUS = "A+"
    A = "A"
    A_MINUS = "A-"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"
    T = "T"
    M = "M"


# Request Models

class ScanOptions(BaseModel):
    """Scan configuration options."""
    model_config = ConfigDict(extra="allow")

    test_protocols: bool = Field(default=False, description="Test all SSL/TLS protocols")
    test_ciphers: bool = Field(default=False, description="Test all cipher suites")
    test_vulnerabilities: bool = Field(default=False, description="Test for vulnerabilities")
    analyze_certificates: bool = Field(default=False, description="Analyze certificate chain")
    test_http_headers: bool = Field(default=False, description="Test HTTP security headers")
    client_simulation: bool = Field(default=False, description="Run client simulations")
    starttls_protocol: Optional[str] = Field(default=None, description="STARTTLS protocol (smtp, imap, pop3, etc.)")
    timeout_seconds: int = Field(default=30, description="Connection timeout in seconds")
    ipv4_only: bool = Field(default=False, description="Use IPv4 only")
    ipv6_only: bool = Field(default=False, description="Use IPv6 only")
    ip: Optional[str] = Field(default=None, description="Specific IP address to test")
    full_scan: bool = Field(default=False, description="Run full comprehensive scan")

    @classmethod
    def full(cls) -> "ScanOptions":
        """Create options for a full comprehensive scan."""
        return cls(
            test_protocols=True,
            test_ciphers=True,
            test_vulnerabilities=True,
            analyze_certificates=True,
            test_http_headers=True,
            client_simulation=True,
            full_scan=True,
        )

    @classmethod
    def quick(cls) -> "ScanOptions":
        """Create options for a quick scan."""
        return cls(
            test_protocols=True,
            test_ciphers=False,
            test_vulnerabilities=False,
            analyze_certificates=True,
            test_http_headers=False,
            client_simulation=False,
        )


class ScanRequest(BaseModel):
    """Request to create a new scan."""
    model_config = ConfigDict(extra="allow")

    target: str = Field(..., description="Target to scan (hostname:port or just hostname)")
    options: ScanOptions = Field(default_factory=ScanOptions, description="Scan options")
    webhook_url: Optional[str] = Field(default=None, description="Webhook URL to call when scan completes")


class PolicyRequest(BaseModel):
    """Request to create or update a policy."""
    model_config = ConfigDict(extra="allow")

    name: str = Field(..., description="Policy name")
    description: Optional[str] = Field(default=None, description="Policy description")
    rules: str = Field(..., description="Policy rules in YAML format")
    enabled: bool = Field(default=True, description="Policy enabled status")


class PolicyEvaluationRequest(BaseModel):
    """Request to evaluate a target against a policy."""
    model_config = ConfigDict(extra="allow")

    target: str = Field(..., description="Target to evaluate")
    options: ScanOptions = Field(default_factory=ScanOptions, description="Scan options")


class ComplianceCheckRequest(BaseModel):
    """Request for compliance check."""
    model_config = ConfigDict(extra="allow")

    target: str = Field(..., description="Target to check")
    framework: str = Field(..., description="Compliance framework (pci-dss-v4, nist-sp800-52r2, etc.)")
    detailed: bool = Field(default=False, description="Generate detailed report")


# Response Models

class ScanResponse(BaseModel):
    """Response when creating a scan."""
    model_config = ConfigDict(extra="allow")

    scan_id: str = Field(..., description="Unique scan ID")
    status: ScanStatus = Field(..., description="Current scan status")
    target: str = Field(..., description="Target being scanned")
    websocket_url: Optional[str] = Field(default=None, description="WebSocket URL for real-time progress")
    queued_at: datetime = Field(..., description="When the scan was queued")
    estimated_completion: Optional[datetime] = Field(default=None, description="Estimated completion time")


class ScanStatusResponse(BaseModel):
    """Response for scan status."""
    model_config = ConfigDict(extra="allow")

    scan_id: str = Field(..., description="Unique scan ID")
    status: ScanStatus = Field(..., description="Current status")
    progress: int = Field(..., description="Progress percentage (0-100)")
    current_stage: Optional[str] = Field(default=None, description="Current stage being executed")
    eta_seconds: Optional[int] = Field(default=None, description="Estimated seconds until completion")
    started_at: Optional[datetime] = Field(default=None, description="When scan started")
    completed_at: Optional[datetime] = Field(default=None, description="When scan completed")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    results_url: Optional[str] = Field(default=None, description="Link to results (if completed)")


class ProgressMessage(BaseModel):
    """WebSocket progress message."""
    model_config = ConfigDict(extra="allow")

    msg_type: str = Field(..., description="Message type")
    scan_id: str = Field(..., description="Scan ID")
    progress: int = Field(..., description="Progress percentage (0-100)")
    stage: str = Field(..., description="Current stage")
    details: Optional[str] = Field(default=None, description="Stage details")
    timestamp: datetime = Field(..., description="Timestamp")


class CertificateSummary(BaseModel):
    """Certificate summary information."""
    model_config = ConfigDict(extra="allow")

    fingerprint: str = Field(..., description="SHA-256 fingerprint")
    common_name: str = Field(..., description="Subject common name")
    san: List[str] = Field(default_factory=list, description="Subject alternative names")
    issuer: str = Field(..., description="Issuer")
    valid_from: datetime = Field(..., description="Valid from date")
    valid_until: datetime = Field(..., description="Valid until date")
    days_until_expiry: int = Field(..., description="Days until expiry")
    is_expired: bool = Field(..., description="Certificate is expired")
    is_expiring_soon: bool = Field(..., description="Certificate is expiring soon (<30 days)")
    hostnames: List[str] = Field(default_factory=list, description="Associated hostnames")


class CertificateListResponse(BaseModel):
    """Response for certificate list."""
    model_config = ConfigDict(extra="allow")

    total: int = Field(..., description="Total count of certificates")
    offset: int = Field(..., description="Current page offset")
    limit: int = Field(..., description="Page size limit")
    certificates: List[CertificateSummary] = Field(default_factory=list, description="Certificate summaries")


class PolicyCheckResult(BaseModel):
    """Individual policy check result."""
    model_config = ConfigDict(extra="allow")

    check: str = Field(..., description="Check name")
    passed: bool = Field(..., description="Check passed")
    severity: str = Field(..., description="Severity level")
    message: Optional[str] = Field(default=None, description="Failure message if not passed")
    expected: Optional[str] = Field(default=None, description="Expected value")
    actual: Optional[str] = Field(default=None, description="Actual value")


class PolicyResponse(BaseModel):
    """Policy details response."""
    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Policy ID")
    name: str = Field(..., description="Policy name")
    description: Optional[str] = Field(default=None, description="Description")
    rules: str = Field(..., description="Rules in YAML format")
    enabled: bool = Field(..., description="Enabled status")
    created_at: datetime = Field(..., description="Created timestamp")
    updated_at: datetime = Field(..., description="Updated timestamp")


class PolicyEvaluationResponse(BaseModel):
    """Policy evaluation result."""
    model_config = ConfigDict(extra="allow")

    policy_id: str = Field(..., description="Policy ID")
    policy_name: str = Field(..., description="Policy name")
    target: str = Field(..., description="Target evaluated")
    compliant: bool = Field(..., description="Overall compliance status")
    checks: List[PolicyCheckResult] = Field(default_factory=list, description="Individual check results")
    evaluated_at: datetime = Field(..., description="Evaluation timestamp")
    scan_id: str = Field(..., description="Scan used for evaluation")


class HealthResponse(BaseModel):
    """Health check response."""
    model_config = ConfigDict(extra="allow")

    status: str = Field(..., description="Service status")
    version: str = Field(..., description="Service version")
    uptime_seconds: int = Field(..., description="Uptime in seconds")
    active_scans: int = Field(..., description="Current number of active scans")
    queued_scans: int = Field(..., description="Queued scans")
    database: Optional[str] = Field(default=None, description="Database connection status")


class DomainStats(BaseModel):
    """Domain statistics."""
    model_config = ConfigDict(extra="allow")

    domain: str = Field(..., description="Domain name")
    scan_count: int = Field(..., description="Number of scans")
    last_scan: datetime = Field(..., description="Last scan time")


class ApiUsageStats(BaseModel):
    """API usage statistics."""
    model_config = ConfigDict(extra="allow")

    requests_last_hour: int = Field(..., description="Requests in last hour")
    requests_last_day: int = Field(..., description="Requests in last day")
    avg_response_time_ms: float = Field(..., description="Average response time in milliseconds")


class StatsResponse(BaseModel):
    """API statistics response."""
    model_config = ConfigDict(extra="allow")

    total_scans: int = Field(..., description="Total scans performed")
    completed_scans: int = Field(..., description="Completed scans")
    failed_scans: int = Field(..., description="Failed scans")
    avg_scan_duration_seconds: float = Field(..., description="Average scan duration in seconds")
    scans_last_24h: int = Field(..., description="Scans in last 24 hours")
    scans_last_7d: int = Field(..., description="Scans in last 7 days")
    top_domains: List[DomainStats] = Field(default_factory=list, description="Most scanned domains (top 10)")
    api_usage: ApiUsageStats = Field(..., description="Current API usage statistics")


class HistoricalScan(BaseModel):
    """Historical scan record."""
    model_config = ConfigDict(extra="allow")

    scan_id: str = Field(..., description="Scan ID")
    timestamp: datetime = Field(..., description="Scan timestamp")
    grade: Optional[str] = Field(default=None, description="Overall grade")
    score: Optional[int] = Field(default=None, description="Overall score")
    duration_ms: int = Field(..., description="Scan duration in milliseconds")
    vulnerability_count: int = Field(..., description="Number of vulnerabilities found")
    results_url: str = Field(..., description="Link to full results")


class ScanHistoryResponse(BaseModel):
    """Scan history response."""
    model_config = ConfigDict(extra="allow")

    domain: str = Field(..., description="Domain")
    port: int = Field(..., description="Port")
    total_scans: int = Field(..., description="Total scans in history")
    scans: List[HistoricalScan] = Field(default_factory=list, description="Historical scan records")


# Scan Results Models

class ProtocolTestResult(BaseModel):
    """Protocol test result."""
    model_config = ConfigDict(extra="allow")

    protocol: str = Field(..., description="Protocol name")
    supported: bool = Field(..., description="Whether protocol is supported")
    handshake_time_ms: Optional[int] = Field(default=None, description="Handshake time in milliseconds")
    heartbeat_enabled: Optional[bool] = Field(default=None, description="Heartbeat extension enabled")


class CipherInfo(BaseModel):
    """Cipher suite information."""
    model_config = ConfigDict(extra="allow")

    iana_name: str = Field(..., description="IANA cipher name")
    openssl_name: str = Field(..., description="OpenSSL cipher name")
    hexcode: str = Field(..., description="Cipher hexadecimal code")
    key_exchange: str = Field(..., description="Key exchange algorithm")
    authentication: str = Field(..., description="Authentication algorithm")
    encryption: str = Field(..., description="Encryption algorithm")
    bits: int = Field(..., description="Encryption key size in bits")
    mac: str = Field(..., description="MAC algorithm")


class CipherCounts(BaseModel):
    """Cipher suite counts and statistics."""
    model_config = ConfigDict(extra="allow")

    total: int = Field(default=0, description="Total cipher suites")
    null_ciphers: int = Field(default=0, description="NULL ciphers (no encryption)")
    export_ciphers: int = Field(default=0, description="EXPORT ciphers (weak)")
    low_strength: int = Field(default=0, description="Low strength ciphers")
    medium_strength: int = Field(default=0, description="Medium strength ciphers")
    high_strength: int = Field(default=0, description="High strength ciphers")
    forward_secrecy: int = Field(default=0, description="Ciphers with forward secrecy")
    aead: int = Field(default=0, description="AEAD ciphers")


class ProtocolCipherSummary(BaseModel):
    """Cipher summary for a protocol."""
    model_config = ConfigDict(extra="allow")

    protocol: str = Field(..., description="Protocol name")
    supported_ciphers: List[CipherInfo] = Field(default_factory=list, description="Supported cipher suites")
    counts: CipherCounts = Field(default_factory=CipherCounts, description="Cipher statistics")
    server_ordered: bool = Field(default=False, description="Server enforces cipher order")
    preferred_cipher: Optional[CipherInfo] = Field(default=None, description="Server's preferred cipher")
    avg_handshake_time_ms: Optional[int] = Field(default=None, description="Average handshake time")


class CertificateInfo(BaseModel):
    """Certificate information."""
    model_config = ConfigDict(extra="allow")

    subject: str = Field(..., description="Certificate subject")
    issuer: str = Field(..., description="Certificate issuer")
    not_before: str = Field(..., description="Valid from date")
    not_after: str = Field(..., description="Valid until date")
    serial_number: str = Field(..., description="Serial number")
    public_key_algorithm: str = Field(..., description="Public key algorithm")
    public_key_size: Optional[int] = Field(default=None, description="Public key size in bits")
    signature_algorithm: str = Field(..., description="Signature algorithm")
    fingerprint_sha256: Optional[str] = Field(default=None, description="SHA-256 fingerprint")
    pin_sha256: Optional[str] = Field(default=None, description="Pin SHA-256 (HPKP)")
    san: List[str] = Field(default_factory=list, description="Subject Alternative Names")
    expiry_countdown: Optional[str] = Field(default=None, description="Expiry countdown")


class ValidationIssue(BaseModel):
    """Certificate validation issue."""
    model_config = ConfigDict(extra="allow")

    severity: str = Field(..., description="Issue severity")
    description: str = Field(..., description="Issue description")


class ValidationResult(BaseModel):
    """Certificate validation result."""
    model_config = ConfigDict(extra="allow")

    valid: bool = Field(..., description="Overall validity")
    hostname_match: bool = Field(..., description="Hostname matches certificate")
    not_expired: bool = Field(..., description="Certificate not expired")
    trust_chain_valid: bool = Field(..., description="Trust chain is valid")
    trusted_ca: Optional[str] = Field(default=None, description="Trusted CA name")
    issues: List[ValidationIssue] = Field(default_factory=list, description="Validation issues")


class RevocationResult(BaseModel):
    """Certificate revocation check result."""
    model_config = ConfigDict(extra="allow")

    status: str = Field(..., description="Revocation status")
    method: str = Field(..., description="Check method (OCSP, CRL, etc.)")
    must_staple: bool = Field(default=False, description="Must-Staple extension present")


class CertificateChain(BaseModel):
    """Certificate chain information."""
    model_config = ConfigDict(extra="allow")

    certificates: List[CertificateInfo] = Field(default_factory=list, description="Certificate chain")
    chain_length: int = Field(..., description="Chain length")
    chain_size_bytes: int = Field(..., description="Chain size in bytes")


class CertificateAnalysisResult(BaseModel):
    """Complete certificate analysis result."""
    model_config = ConfigDict(extra="allow")

    chain: CertificateChain = Field(..., description="Certificate chain")
    validation: ValidationResult = Field(..., description="Validation result")
    revocation: Optional[RevocationResult] = Field(default=None, description="Revocation check result")


class HeaderIssue(BaseModel):
    """HTTP header security issue."""
    model_config = ConfigDict(extra="allow")

    header_name: str = Field(..., description="Header name")
    severity: str = Field(..., description="Issue severity")
    issue_type: str = Field(..., description="Issue type")
    description: str = Field(..., description="Issue description")
    recommendation: str = Field(..., description="Recommendation")


class HeaderAnalysisResult(BaseModel):
    """HTTP security headers analysis result."""
    model_config = ConfigDict(extra="allow")

    grade: str = Field(..., description="Security grade")
    score: int = Field(..., description="Security score (0-100)")
    issues: List[HeaderIssue] = Field(default_factory=list, description="Security issues found")
    http_status_code: Optional[int] = Field(default=None, description="HTTP status code")
    server_hostname: Optional[str] = Field(default=None, description="Server hostname")


class VulnerabilityResult(BaseModel):
    """Vulnerability test result."""
    model_config = ConfigDict(extra="allow")

    vuln_type: str = Field(..., description="Vulnerability type")
    vulnerable: bool = Field(..., description="Whether target is vulnerable")
    severity: Severity = Field(..., description="Severity level")
    details: str = Field(..., description="Vulnerability details")
    cve: Optional[str] = Field(default=None, description="CVE identifier")


class ClientSimulationResult(BaseModel):
    """Client simulation result."""
    model_config = ConfigDict(extra="allow")

    client_name: str = Field(..., description="Client name")
    success: bool = Field(..., description="Connection succeeded")
    protocol: Optional[str] = Field(default=None, description="Protocol used")
    cipher: Optional[str] = Field(default=None, description="Cipher used")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    handshake_time_ms: Optional[int] = Field(default=None, description="Handshake time")


class RatingResult(BaseModel):
    """SSL Labs style rating result."""
    model_config = ConfigDict(extra="allow")

    grade: SecurityGrade = Field(..., description="Overall grade")
    score: int = Field(..., description="Overall score (0-100)")
    certificate_score: int = Field(..., description="Certificate score")
    protocol_score: int = Field(..., description="Protocol score")
    key_exchange_score: int = Field(..., description="Key exchange score")
    cipher_strength_score: int = Field(..., description="Cipher strength score")
    warnings: List[str] = Field(default_factory=list, description="Warnings")


class ScanResults(BaseModel):
    """Complete scan results."""
    model_config = ConfigDict(extra="allow")

    target: str = Field(..., description="Target scanned")
    scan_time_ms: int = Field(..., description="Total scan time in milliseconds")
    protocols: List[ProtocolTestResult] = Field(default_factory=list, description="Protocol test results")
    ciphers: Dict[str, ProtocolCipherSummary] = Field(default_factory=dict, description="Cipher test results")
    certificate_chain: Optional[CertificateAnalysisResult] = Field(default=None, description="Certificate analysis")
    http_headers: Optional[HeaderAnalysisResult] = Field(default=None, description="HTTP headers analysis")
    vulnerabilities: List[VulnerabilityResult] = Field(default_factory=list, description="Vulnerability results")
    client_simulations: Optional[List[ClientSimulationResult]] = Field(default=None, description="Client simulations")
    rating: Optional[RatingResult] = Field(default=None, description="SSL Labs rating")


class ComplianceReport(BaseModel):
    """Compliance check report."""
    model_config = ConfigDict(extra="allow")

    framework: str = Field(..., description="Compliance framework")
    status: str = Field(..., description="Compliance status")
    message: Optional[str] = Field(default=None, description="Status message")


class ApiErrorResponse(BaseModel):
    """API error response."""
    model_config = ConfigDict(extra="allow")

    status: int = Field(..., description="HTTP status code")
    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    details: Optional[str] = Field(default=None, description="Error details")
