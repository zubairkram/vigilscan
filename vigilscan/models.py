"""
Data models and structure definitions for VigilScan.
Zero external dependencies; uses Python standard library dataclasses.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone


@dataclass
class PortResult:
    """Represents a scanned port and its detected state/service."""
    port: int
    protocol: str = "tcp"
    state: str = "closed"          # open, closed, filtered
    service_name: str = "unknown"
    banner: str = ""
    response_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TlsAuditResult:
    """Detailed SSL/TLS cryptographic audit result."""
    has_tls: bool = False
    subject: str = ""
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    days_remaining: int = 0
    is_expired: bool = False
    is_expiring_soon: bool = False  # < 30 days
    is_self_signed: bool = False
    tls_version: str = ""
    cipher_name: str = ""
    san_list: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HttpAuditResult:
    """Web service security header & configuration audit result."""
    status_code: Optional[int] = None
    server_header: str = ""
    powered_by_header: str = ""
    missing_headers: List[str] = field(default_factory=list)
    present_headers: Dict[str, str] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Vulnerability:
    """Security finding / vulnerability definition with risk scoring."""
    vuln_id: str
    title: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cwe_id: str
    port: Optional[int]
    description: str
    remediation: str
    cvss_estimate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostScanReport:
    """Consolidated host audit report."""
    target: str
    ip_address: str
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    duration_seconds: float = 0.0
    total_ports_scanned: int = 0
    open_ports: List[PortResult] = field(default_factory=list)
    tls_audit: Optional[TlsAuditResult] = None
    http_audit: Optional[HttpAuditResult] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    security_score: int = 100
    risk_rating: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data
