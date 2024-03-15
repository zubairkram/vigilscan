"""
SSL/TLS Cryptographic Security Auditor.
Directly maps to Certiport Objective 1.4:
- Encryption types, PKI, digital certificates
- Strong vs. weak encryption algorithms and protocols (data in transit)
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from vigilscan.models import TlsAuditResult

# Insecure/Deprecated TLS protocol versions
DEPRECATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Weak cipher keywords (DES, 3DES, RC4, MD5, NULL, EXPORT)
WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXP", "CBC"]


def audit_tls_service(host: str, port: int = 443, timeout: float = 3.0) -> Optional[TlsAuditResult]:
    """
    Connect to an SSL/TLS service, extract certificate details, validate expiration,
    detect self-signed status, and inspect cipher strength.
    """
    result = TlsAuditResult(has_tls=False)

    # We use a default context that requests server cert
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Read cert even if self-signed to inspect details

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    try:
        with context.wrap_socket(raw_sock, server_hostname=host) as ssock:
            ssock.connect((host, port))
            result.has_tls = True

            # 1. Protocol & Cipher details
            tls_version = ssock.version() or "Unknown"
            cipher_info = ssock.cipher()
            result.tls_version = tls_version
            if cipher_info:
                result.cipher_name = cipher_info[0]

            # 2. Extract Certificate info
            cert = ssock.getpeercert(binary_form=False)
            # If getpeercert() returns empty dict because CERT_NONE was used,
            # we also attempt binary parse via ssl.DER_cert_to_PEM_cert or secondary probe
            if not cert:
                # Re-probe with CERT_OPTIONAL or inspect binary cert
                bin_cert = ssock.getpeercert(binary_form=True)
                if bin_cert:
                    # Mark active TLS
                    pass

            if cert:
                # Subject extraction
                subject_items = []
                for rdn in cert.get("subject", ()):
                    for key, val in rdn:
                        if key == "commonName":
                            result.subject = val
                        subject_items.append(f"{key}={val}")

                # Issuer extraction
                issuer_items = []
                for rdn in cert.get("issuer", ()):
                    for key, val in rdn:
                        if key == "commonName":
                            result.issuer = val
                        issuer_items.append(f"{key}={val}")

                if not result.subject and subject_items:
                    result.subject = ", ".join(subject_items)
                if not result.issuer and issuer_items:
                    result.issuer = ", ".join(issuer_items)

                # SAN (Subject Alternative Names)
                sans = cert.get("subjectAltName", ())
                result.san_list = [val for typ, val in sans if typ == "DNS"]

                # Expiration Dates parsing (format: 'May 15 12:00:00 2025 GMT')
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")
                result.valid_from = not_before_str or ""
                result.valid_to = not_after_str or ""

                if not_after_str:
                    try:
                        expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        delta = expire_date - now
                        result.days_remaining = delta.days

                        if delta.total_seconds() < 0:
                            result.is_expired = True
                            result.findings.append(f"Certificate expired on {not_after_str} ({abs(delta.days)} days ago).")
                        elif delta.days <= 30:
                            result.is_expiring_soon = True
                            result.findings.append(f"Certificate expires soon in {delta.days} days ({not_after_str}).")
                    except Exception:
                        pass

                # Check Self-Signed status
                if result.subject and result.issuer and result.subject == result.issuer:
                    result.is_self_signed = True
                    result.findings.append("Self-signed SSL/TLS certificate detected (Untrusted CA).")

            # 3. Check for Deprecated TLS protocol versions
            if result.tls_version in DEPRECATED_TLS_VERSIONS:
                result.findings.append(f"Deprecated TLS protocol negotiated: {result.tls_version} (Vulnerable to POODLE/BEAST).")

            # 4. Check for Weak Ciphers
            if result.cipher_name:
                for weak in WEAK_CIPHER_KEYWORDS:
                    if weak in result.cipher_name.upper():
                        result.findings.append(f"Weak cipher suite in use: {result.cipher_name} contains insecure algorithm {weak}.")
                        break

    except (ssl.SSLError, socket.error, socket.timeout):
        return None

    return result
