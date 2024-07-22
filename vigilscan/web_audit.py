"""
HTTP/HTTPS Web Security Header & Configuration Auditor.
Audits web services for missing hardening headers and information leakage.
"""

import socket
import ssl
from typing import Optional, Dict, List
from vigilscan.models import HttpAuditResult

# Essential HTTP Security Headers and their security implications
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS enforces secure HTTPS connections to defeat downgrade/SSL-stripping attacks.",
    "Content-Security-Policy": "CSP mitigates Cross-Site Scripting (XSS) and data injection attacks.",
    "X-Frame-Options": "Prevents Clickjacking attacks by disallowing malicious framing.",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks by enforcing declared content-types (nosniff).",
    "Referrer-Policy": "Controls how much referral information is sent with requests, avoiding data leakage.",
    "Permissions-Policy": "Restricts browser features like camera, microphone, and geolocation access.",
}


def audit_http_service(host: str, port: int = 80, use_tls: bool = False, timeout: float = 2.5) -> Optional[HttpAuditResult]:
    """
    Connect to a web port, perform an HTTP request, and analyze headers for security posture.
    """
    result = HttpAuditResult()
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        sock.connect((host, port))
        
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) VigilScan/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode("ascii"))

        # Read response up to 8KB to inspect headers
        response_bytes = b""
        while len(response_bytes) < 8192:
            chunk = sock.recv(2048)
            if not chunk:
                break
            response_bytes += chunk
            if b"\r\n\r\n" in response_bytes:
                break

        response_text = response_bytes.decode("utf-8", errors="replace")
        header_section = response_text.split("\r\n\r\n")[0]
        lines = header_section.split("\r\n")

        if not lines:
            return None

        # Parse HTTP status code (e.g., HTTP/1.1 200 OK)
        status_line = lines[0]
        status_parts = status_line.split()
        if len(status_parts) >= 2 and status_parts[1].isdigit():
            result.status_code = int(status_parts[1])

        # Parse headers into dict (case-insensitive keys)
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
                result.present_headers[k.strip()] = v.strip()

        # Check for information leakage
        server_val = headers.get("server", "")
        if server_val:
            result.server_header = server_val
            result.findings.append(f"Server banner exposed: '{server_val}' (Assists attacker fingerprinting).")

        powered_val = headers.get("x-powered-by", "")
        if powered_val:
            result.powered_by_header = powered_val
            result.findings.append(f"Technology disclosure: 'X-Powered-By: {powered_val}'.")

        # Evaluate Security Headers
        for sec_hdr, description in SECURITY_HEADERS.items():
            if sec_hdr.lower() not in headers:
                result.missing_headers.append(sec_hdr)
                result.findings.append(f"Missing security header: {sec_hdr} ({description})")

    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result
