"""
Scan orchestrator and core controller for VigilScan.
Coordinates port discovery, banner grabbing, TLS auditing, web inspection, and risk rating.
"""

import time
from typing import List, Optional, Callable
from vigilscan.models import HostScanReport, PortResult, TlsAuditResult, HttpAuditResult
from vigilscan.network import resolve_target, scan_ports
from vigilscan.banner import grab_banner
from vigilscan.tls_audit import audit_tls_service
from vigilscan.web_audit import audit_http_service
from vigilscan.risk_engine import analyze_vulnerabilities


def execute_host_audit(
    target: str,
    ports: List[int],
    threads: int = 50,
    timeout: float = 1.0,
    progress_callback: Optional[Callable[[PortResult], None]] = None,
    status_callback: Optional[Callable[[str], None]] = None
) -> HostScanReport:
    """
    Run an end-to-end security audit against a target host.
    """
    if status_callback:
        status_callback(f"Resolving target '{target}'...")

    target_name, canonical_ip = resolve_target(target)

    start_time = time.perf_counter()

    if status_callback:
        status_callback(f"Initiating concurrent port probe on {len(ports)} ports ({threads} threads)...")

    # 1. Network Port Scan
    open_ports = scan_ports(
        canonical_ip, 
        ports, 
        threads=threads, 
        timeout=timeout, 
        callback=progress_callback
    )

    if status_callback:
        status_callback(f"Discovered {len(open_ports)} open port(s). Commencing service banner analysis...")

    # 2. Service Banner Grabbing
    for p in open_ports:
        banner = grab_banner(canonical_ip, p.port, timeout=timeout + 0.5)
        p.banner = banner

    open_port_numbers = {p.port for p in open_ports}

    # 3. SSL/TLS Audit (Domain 1.4)
    tls_result: Optional[TlsAuditResult] = None
    tls_ports = [p for p in (443, 8443, 9443) if p in open_port_numbers]
    if tls_ports:
        if status_callback:
            status_callback(f"Performing cryptographic SSL/TLS handshake & PKI audit on port {tls_ports[0]}...")
        # Use target_name for SNI hostname verification
        tls_result = audit_tls_service(target_name, port=tls_ports[0], timeout=3.0)

    # 4. HTTP Security Headers Audit (Domain 2.1 & 4.1)
    http_result: Optional[HttpAuditResult] = None
    if 443 in open_port_numbers:
        if status_callback:
            status_callback("Auditing HTTPS security headers (HSTS, CSP, X-Frame-Options)...")
        http_result = audit_http_service(target_name, port=443, use_tls=True, timeout=2.5)
    elif 80 in open_port_numbers:
        if status_callback:
            status_callback("Auditing HTTP security headers...")
        http_result = audit_http_service(target_name, port=80, use_tls=False, timeout=2.5)

    if status_callback:
        status_callback("Running vulnerability assessment and risk scoring algorithms...")

    # 5. Vulnerability and Risk Analysis (Domain 4.3)
    vulns, score, rating = analyze_vulnerabilities(
        open_ports=open_ports,
        tls_audit=tls_result,
        http_audit=http_result
    )

    duration = round(time.perf_counter() - start_time, 2)

    report = HostScanReport(
        target=target_name,
        ip_address=canonical_ip,
        duration_seconds=duration,
        total_ports_scanned=len(ports),
        open_ports=open_ports,
        tls_audit=tls_result,
        http_audit=http_result,
        vulnerabilities=vulns,
        security_score=score,
        risk_rating=rating
    )

    return report
