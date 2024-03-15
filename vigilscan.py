#!/usr/bin/env python3
"""
VigilScan - Lightweight Network Vulnerability Scanner & Posture Auditor
Entrypoint CLI.
Aligned with Certiport IT Specialist: Cybersecurity Exam Objectives.
"""

import sys
import os
import argparse

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vigilscan.core import execute_host_audit
from vigilscan.network import parse_port_range
from vigilscan.models import HostScanReport, PortResult, TlsAuditResult, HttpAuditResult, Vulnerability
from vigilscan.reporter import print_cli_banner, print_cli_summary, generate_html_report, export_json, COLOR_CYAN, COLOR_RESET, COLOR_GREEN


def run_demo_mode(output_html: str = "reports/demo_audit_report.html", output_json: str = "reports/demo_audit_report.json"):
    """
    Run an offline demonstration audit showcasing all Certiport objective capabilities:
    - Open ports & banners
    - Deprecated TLS & expiring certificates
    - Missing HTTP security headers
    - Risk rating and CVSS/CWE scoring
    - Interactive HTML Report generation
    """
    print(f"{COLOR_CYAN}[DEMO MODE]{COLOR_RESET} Simulating comprehensive vulnerability audit on enterprise perimeter host...")
    
    mock_open_ports = [
        PortResult(port=21, protocol="tcp", state="open", service_name="FTP (File Transfer)", banner="220 (vsFTPd 3.0.3) ready.", response_time_ms=12.4),
        PortResult(port=22, protocol="tcp", state="open", service_name="SSH (Secure Shell)", banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", response_time_ms=9.1),
        PortResult(port=23, protocol="tcp", state="open", service_name="Telnet (Unencrypted CLI)", banner="Linux Telnet Service (Insecure)", response_time_ms=15.2),
        PortResult(port=80, protocol="tcp", state="open", service_name="HTTP (Web Traffic)", banner="HTTP/1.1 200 OK | Server: Apache/2.4.41 (Ubuntu)", response_time_ms=8.5),
        PortResult(port=443, protocol="tcp", state="open", service_name="HTTPS (Encrypted Web)", banner="HTTP/1.1 200 OK | Server: Apache/2.4.41 (Ubuntu)", response_time_ms=14.8),
        PortResult(port=3306, protocol="tcp", state="open", service_name="MySQL Database", banner="5.7.33-0ubuntu0.18.04.1", response_time_ms=18.0),
        PortResult(port=3389, protocol="tcp", state="open", service_name="RDP (Remote Desktop)", banner="MS Remote Desktop Terminal Server", response_time_ms=22.3),
    ]

    mock_tls = TlsAuditResult(
        has_tls=True,
        subject="gateway.internal.corp",
        issuer="gateway.internal.corp",  # Self-signed
        valid_from="Jan 15 00:00:00 2024 GMT",
        valid_to="Jan 15 00:00:00 2025 GMT",
        days_remaining=-288,
        is_expired=True,
        is_self_signed=True,
        tls_version="TLSv1.1",  # Deprecated
        cipher_name="ECDHE-RSA-AES256-SHA",
        san_list=["gateway.internal.corp", "vpn.internal.corp"],
        findings=[
            "Certificate expired on Jan 15 00:00:00 2025 GMT (288 days ago).",
            "Self-signed SSL/TLS certificate detected (Untrusted CA).",
            "Deprecated TLS protocol negotiated: TLSv1.1 (Vulnerable to POODLE/BEAST)."
        ]
    )

    mock_http = HttpAuditResult(
        status_code=200,
        server_header="Apache/2.4.41 (Ubuntu)",
        powered_by_header="PHP/7.4.3",
        missing_headers=["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"],
        present_headers={"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
        findings=[
            "Server banner exposed: 'Apache/2.4.41 (Ubuntu)' (Assists attacker fingerprinting).",
            "Technology disclosure: 'X-Powered-By: PHP/7.4.3'.",
            "Missing security header: Strict-Transport-Security",
            "Missing security header: Content-Security-Policy",
            "Missing security header: X-Frame-Options"
        ]
    )

    from vigilscan.risk_engine import analyze_vulnerabilities
    vulns, score, rating = analyze_vulnerabilities(
        open_ports=mock_open_ports,
        tls_audit=mock_tls,
        http_audit=mock_http
    )

    report = HostScanReport(
        target="corp-gateway.demo.local",
        ip_address="192.168.10.45",
        duration_seconds=1.45,
        total_ports_scanned=25,
        open_ports=mock_open_ports,
        tls_audit=mock_tls,
        http_audit=mock_http,
        vulnerabilities=vulns,
        security_score=score,
        risk_rating=rating
    )

    print_cli_summary(report)

    if output_html:
        generate_html_report(report, output_html)
        print(f"{COLOR_GREEN}[+] HTML Security Dashboard generated: {os.path.abspath(output_html)}{COLOR_RESET}")

    if output_json:
        export_json(report, output_json)
        print(f"{COLOR_GREEN}[+] Machine-readable JSON exported: {os.path.abspath(output_json)}{COLOR_RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="VigilScan - Lightweight Network Vulnerability Scanner & Security Posture Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vigilscan.py 127.0.0.1
  python vigilscan.py scanme.nmap.org -p quick --html reports/audit.html
  python vigilscan.py example.com -p 80,443,8080,8443 --threads 20
  python vigilscan.py --demo
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target IP address or hostname to audit (e.g. 192.168.1.1 or scanme.nmap.org)")
    parser.add_argument("-p", "--ports", default="quick", help="Ports to scan: 'quick', 'all', or list/range '80,443,8000-8080' (default: quick)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent worker threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket connect timeout in seconds (default: 1.0)")
    parser.add_argument("--html", default="reports/audit_report.html", help="Path to output HTML report (default: reports/audit_report.html)")
    parser.add_argument("--json", help="Path to output JSON report (optional)")
    parser.add_argument("--demo", action="store_true", help="Run in demonstration mode to showcase scanner capabilities and reports")
    parser.add_argument("--no-banner", action="store_true", help="Suppress ASCII header banner")

    args = parser.parse_args()

    if not args.no_banner:
        print_cli_banner()

    if args.demo:
        run_demo_mode(output_html=args.html, output_json=args.json or "reports/demo_audit_report.json")
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    try:
        ports = parse_port_range(args.ports)
    except ValueError as e:
        print(f"Error parsing port specifications: {e}", file=sys.stderr)
        sys.exit(1)

    def status_callback(msg: str):
        print(f"{COLOR_CYAN}[*]{COLOR_RESET} {msg}")

    try:
        report = execute_host_audit(
            target=args.target,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout,
            status_callback=status_callback
        )
    except Exception as e:
        print(f"Error during scan: {e}", file=sys.stderr)
        sys.exit(1)

    print_cli_summary(report)

    if args.html:
        generate_html_report(report, args.html)
        print(f"{COLOR_GREEN}[+] HTML Security Dashboard generated: {os.path.abspath(args.html)}{COLOR_RESET}")

    if args.json:
        export_json(report, args.json)
        print(f"{COLOR_GREEN}[+] JSON Report saved: {os.path.abspath(args.json)}{COLOR_RESET}")



if __name__ == "__main__":
    main()
