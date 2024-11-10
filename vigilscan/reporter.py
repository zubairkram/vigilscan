"""
Report generator for VigilScan.
Produces rich terminal output, machine-readable JSON, and professional standalone HTML security dashboards.
"""

import json
import os
import sys
from typing import Dict, Any
from vigilscan.models import HostScanReport

# Reconfigure stdout for UTF-8 on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI color codes for terminal
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_CYAN = "\033[96m"
COLOR_GRAY = "\033[90m"


def print_cli_banner():
    """Print clean ASCII art banner for the tool."""
    banner = f"""{COLOR_CYAN}{COLOR_BOLD}
 __      ___       _ _  _____                  
 \\ \\    / (_)     (_) |/ ____|                 
  \\ \\  / / _  __ _ _| | (___   ___ __ _ _ __   
   \\ \\/ / | |/ _` | | |\\___ \\ / __/ _` | '_ \\  
    \\  /  | | (_| | | |____) | (_| (_| | | | | 
     \\/   |_|\\__, |_|_|_____/ \\___\\__,_|_| |_| 
              __/ |                            
             |___/                             
{COLOR_RESET}{COLOR_GRAY} Network Vulnerability Scanner & Security Posture Auditor
 Automated Reconnaissance & Defense Assessment System{COLOR_RESET}
"""
    print(banner)



def print_cli_summary(report: HostScanReport):
    """Render a clean summary of the scan results in the terminal."""
    # Color-code risk rating
    rating_color = COLOR_GREEN
    if report.risk_rating == "CRITICAL":
        rating_color = COLOR_RED
    elif report.risk_rating == "HIGH":
        rating_color = COLOR_RED
    elif report.risk_rating == "MODERATE":
        rating_color = COLOR_YELLOW

    print(f"\n{COLOR_BOLD}==================== SCAN SUMMARY ===================={COLOR_RESET}")
    print(f"Target:          {COLOR_BOLD}{report.target}{COLOR_RESET} ({report.ip_address})")
    print(f"Scan Duration:   {report.duration_seconds}s across {report.total_ports_scanned} ports")
    print(f"Security Score:  {rating_color}{COLOR_BOLD}{report.security_score}/100{COLOR_RESET} (Risk Rating: {rating_color}{report.risk_rating}{COLOR_RESET})")
    print(f"Open Ports:      {len(report.open_ports)}")
    print(f"Vulnerabilities: {len(report.vulnerabilities)}")
    print(f"{COLOR_BOLD}======================================================{COLOR_RESET}\n")

    # Open Ports Table
    if report.open_ports:
        print(f"{COLOR_BOLD}OPEN PORTS & SERVICES:{COLOR_RESET}")
        print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<28}{'LATENCY':<12}{'BANNER'}")
        print("-" * 75)
        for p in report.open_ports:
            banner_preview = (p.banner[:30] + "...") if len(p.banner) > 30 else p.banner
            print(f"{p.port:<8}{COLOR_GREEN}{p.state:<10}{COLOR_RESET}{p.service_name:<28}{f'{p.response_time_ms}ms':<12}{COLOR_GRAY}{banner_preview}{COLOR_RESET}")
        print()

    # TLS Status
    if report.tls_audit and report.tls_audit.has_tls:
        tls = report.tls_audit
        print(f"{COLOR_BOLD}SSL/TLS CRYPTOGRAPHIC POSTURE & PKI AUDIT:{COLOR_RESET}")
        print(f"  Negotiated Protocol: {COLOR_CYAN}{tls.tls_version}{COLOR_RESET}")
        print(f"  Cipher Suite:        {tls.cipher_name}")
        print(f"  Certificate Subject: {tls.subject}")
        print(f"  Issuer:              {tls.issuer}")
        print(f"  Expiration Date:     {tls.valid_to} ({tls.days_remaining} days remaining)")
        if tls.is_expired:
            print(f"  {COLOR_RED}[!] CRITICAL: Certificate is EXPIRED!{COLOR_RESET}")
        elif tls.is_self_signed:
            print(f"  {COLOR_YELLOW}[!] WARNING: Certificate is SELF-SIGNED!{COLOR_RESET}")
        print()

    # Vulnerabilities List
    if report.vulnerabilities:
        print(f"{COLOR_BOLD}SECURITY FINDINGS & RISK CLASSIFICATIONS:{COLOR_RESET}")
        for v in report.vulnerabilities:
            sev_color = COLOR_RED if v.severity in ("CRITICAL", "HIGH") else (COLOR_YELLOW if v.severity == "MEDIUM" else COLOR_BLUE)
            print(f"  {sev_color}[{v.severity}]{COLOR_RESET} {COLOR_BOLD}{v.title}{COLOR_RESET} (Port: {v.port or 'Host'}, CVSS: {v.cvss_estimate})")
            print(f"    {COLOR_GRAY}Classification:{COLOR_RESET} {v.cwe_id}")
            print(f"    {COLOR_GRAY}Remediation:{COLOR_RESET}    {v.remediation}")
        print()
    else:
        print(f"{COLOR_GREEN}[+] No significant vulnerabilities or high-risk exposures detected.{COLOR_RESET}\n")


def export_json(report: HostScanReport, output_path: str):
    """Write scan results to a structured JSON file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)


def generate_html_report(report: HostScanReport, output_path: str):
    """
    Generate an executive-grade, standalone HTML security report.
    Features dark modern cybersecurity styling, dynamic SVG score gauge,
    interactive filters, and detailed remediation guidance.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # Calculate gauge stroke offset
    score = report.security_score
    dash_array = 283  # 2 * pi * 45
    dash_offset = dash_array - (dash_array * score / 100)

    # Color themes according to score
    if score >= 90:
        accent_color = "#10b981"  # Emerald
        score_label = "EXCELLENT"
    elif score >= 75:
        accent_color = "#3b82f6"  # Blue
        score_label = "GOOD"
    elif score >= 50:
        accent_color = "#f59e0b"  # Amber
        score_label = "MODERATE RISK"
    else:
        accent_color = "#ef4444"  # Red
        score_label = "CRITICAL RISK"

    # Severity counts
    crit_count = sum(1 for v in report.vulnerabilities if v.severity == "CRITICAL")
    high_count = sum(1 for v in report.vulnerabilities if v.severity == "HIGH")
    med_count = sum(1 for v in report.vulnerabilities if v.severity == "MEDIUM")
    low_count = sum(1 for v in report.vulnerabilities if v.severity == "LOW")

    # Generate port rows HTML
    port_rows = ""
    for p in report.open_ports:
        port_rows += f"""
        <tr>
            <td style="font-weight: 600; color: #38bdf8;">{p.port}/{p.protocol.upper()}</td>
            <td><span class="badge badge-open">{p.state.upper()}</span></td>
            <td>{p.service_name}</td>
            <td style="color: #94a3b8;">{p.response_time_ms} ms</td>
            <td style="font-family: monospace; font-size: 0.85rem; color: #cbd5e1;">{p.banner or '—'}</td>
        </tr>
        """
    if not port_rows:
        port_rows = "<tr><td colspan='5' style='text-align: center; color: #94a3b8;'>No open ports identified.</td></tr>"

    # Generate vulnerability cards HTML
    vuln_cards = ""
    for v in report.vulnerabilities:
        badge_class = f"badge-{v.severity.lower()}"
        vuln_cards += f"""
        <div class="vuln-card">
            <div class="vuln-header">
                <div>
                    <span class="badge {badge_class}">{v.severity}</span>
                    <span class="vuln-port">Port {v.port or 'N/A'}</span>
                    <strong class="vuln-title">{v.title}</strong>
                </div>
                <div class="vuln-meta">CVSS Est: <strong>{v.cvss_estimate}</strong></div>
            </div>
            <div class="vuln-cwe">{v.cwe_id}</div>
            <p class="vuln-desc">{v.description}</p>
            <div class="remediation-box">
                <div class="rem-title">Recommended Remediation:</div>
                <p>{v.remediation}</p>
            </div>
        </div>
        """
    if not vuln_cards:
        vuln_cards = """
        <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 1.5rem; text-align: center; color: #34d399;">
            <strong>✓ Clean Security Posture</strong><br>No severe network vulnerabilities or critical misconfigurations detected on scanned ports.
        </div>
        """

    # TLS Card HTML
    tls_html = ""
    if report.tls_audit and report.tls_audit.has_tls:
        tls = report.tls_audit
        status_badge = '<span class="badge badge-critical">EXPIRED</span>' if tls.is_expired else '<span class="badge badge-open">VALID</span>'
        tls_html = f"""
        <div class="card" style="margin-top: 1.5rem;">
            <div class="card-title">SSL/TLS Cryptographic Posture & PKI Audit</div>
            <div class="grid-2">
                <div class="info-group">
                    <span class="label">Certificate Status</span>
                    <span class="val">{status_badge} ({tls.days_remaining} days remaining)</span>
                </div>
                <div class="info-group">
                    <span class="label">Negotiated Protocol</span>
                    <span class="val" style="color: #38bdf8; font-weight: 600;">{tls.tls_version}</span>
                </div>
                <div class="info-group">
                    <span class="label">Cipher Suite</span>
                    <span class="val" style="font-family: monospace;">{tls.cipher_name or 'N/A'}</span>
                </div>
                <div class="info-group">
                    <span class="label">Certificate Subject</span>
                    <span class="val">{tls.subject or 'N/A'}</span>
                </div>
                <div class="info-group">
                    <span class="label">Certificate Issuer</span>
                    <span class="val">{tls.issuer or 'N/A'}</span>
                </div>
                <div class="info-group">
                    <span class="label">Valid Until</span>
                    <span class="val">{tls.valid_to or 'N/A'}</span>
                </div>
            </div>
        </div>
        """

    # Complete HTML Document
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VigilScan Audit Report - {report.target}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-base: #090d16;
            --bg-surface: #111827;
            --bg-card: #1e293b;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #38bdf8;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background-color: var(--bg-base);
            color: var(--text-primary);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.5;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .logo-box {{
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, #0284c7, #06b6d4);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.25rem;
            color: #fff;
            box-shadow: 0 0 15px rgba(6, 182, 212, 0.4);
        }}
        .brand h1 {{
            font-size: 1.4rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .brand p {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
        .scan-meta {{
            text-align: right;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        .scan-meta strong {{
            color: var(--text-primary);
        }}

        /* Executive Overview */
        .overview-grid {{
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        @media (max-width: 768px) {{
            .overview-grid {{ grid-template-columns: 1fr; }}
        }}
        .card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        }}
        .card-title {{
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            font-weight: 600;
            margin-bottom: 1rem;
        }}
        .score-card {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
        }}
        .gauge-svg {{
            width: 140px;
            height: 140px;
        }}
        .gauge-bg {{
            fill: none;
            stroke: #1e293b;
            stroke-width: 8;
        }}
        .gauge-fill {{
            fill: none;
            stroke: {accent_color};
            stroke-width: 8;
            stroke-linecap: round;
            stroke-dasharray: {dash_array};
            stroke-dashoffset: {dash_offset};
            transform: rotate(-90deg);
            transform-origin: 50% 50%;
            transition: stroke-dashoffset 1s ease-out;
        }}
        .score-text {{
            font-size: 2.2rem;
            font-weight: 800;
            fill: var(--text-primary);
            text-anchor: middle;
            dominant-baseline: central;
        }}
        .score-desc {{
            margin-top: 0.75rem;
            font-size: 0.95rem;
            font-weight: 600;
            color: {accent_color};
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            height: 100%;
        }}
        @media (max-width: 600px) {{
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
        .stat-box {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}
        .stat-box .count {{
            font-size: 1.8rem;
            font-weight: 700;
            line-height: 1.1;
        }}
        .stat-box .label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
            text-transform: uppercase;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
        .badge-open {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
        }}
        th {{
            background: var(--bg-card);
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            border-bottom: 1px solid rgba(51, 65, 85, 0.5);
        }}
        tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}

        /* Vulnerabilities Section */
        .vuln-card {{
            background: var(--bg-card);
            border-left: 4px solid var(--border);
            border-radius: 0 8px 8px 0;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }}
        .vuln-card:has(.badge-critical) {{ border-left-color: var(--accent-red); }}
        .vuln-card:has(.badge-high) {{ border-left-color: #f97316; }}
        .vuln-card:has(.badge-medium) {{ border-left-color: var(--accent-yellow); }}
        .vuln-card:has(.badge-low) {{ border-left-color: #3b82f6; }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}
        .vuln-port {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin: 0 0.5rem;
            font-family: monospace;
        }}
        .vuln-title {{
            font-size: 1rem;
        }}
        .vuln-meta {{
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        .vuln-cwe {{
            font-size: 0.8rem;
            color: #38bdf8;
            font-family: monospace;
            margin-bottom: 0.5rem;
        }}
        .vuln-desc {{
            font-size: 0.9rem;
            color: #cbd5e1;
            margin-bottom: 0.75rem;
        }}
        .remediation-box {{
            background: rgba(15, 23, 42, 0.8);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            border: 1px solid rgba(51, 65, 85, 0.4);
            font-size: 0.85rem;
        }}
        .rem-title {{
            font-weight: 600;
            color: #34d399;
            margin-bottom: 0.25rem;
        }}

        /* Info Grid */
        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }}
        .info-group {{
            display: flex;
            flex-direction: column;
        }}
        .info-group .label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}
        .info-group .val {{
            font-size: 0.9rem;
            margin-top: 0.2rem;
            word-break: break-all;
        }}

        footer {{
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="logo-box">V</div>
                <div>
                    <h1>VigilScan Security Audit</h1>
                    <p>Network Vulnerability Scanner & Risk Assessment Engine</p>
                </div>
            </div>
            <div class="scan-meta">
                <div>Target: <strong>{report.target}</strong> ({report.ip_address})</div>
                <div>Timestamp: <strong>{report.scan_timestamp}</strong></div>
                <div>Duration: <strong>{report.duration_seconds}s</strong></div>
            </div>
        </header>

        <!-- Executive Overview -->
        <div class="overview-grid">
            <div class="card score-card">
                <div class="card-title">Security Posture Score</div>
                <svg class="gauge-svg" viewBox="0 0 100 100">
                    <circle class="gauge-bg" cx="50" cy="50" r="45"></circle>
                    <circle class="gauge-fill" cx="50" cy="50" r="45"></circle>
                    <text class="score-text" x="50" y="52">{score}</text>
                </svg>
                <div class="score-desc">{score_label}</div>
            </div>
            <div class="card">
                <div class="card-title">Risk Findings & Severity Breakdown</div>
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="count" style="color: var(--accent-red);">{crit_count}</div>
                        <div class="label">Critical</div>
                    </div>
                    <div class="stat-box">
                        <div class="count" style="color: #f97316;">{high_count}</div>
                        <div class="label">High</div>
                    </div>
                    <div class="stat-box">
                        <div class="count" style="color: var(--accent-yellow);">{med_count}</div>
                        <div class="label">Medium</div>
                    </div>
                    <div class="stat-box">
                        <div class="count" style="color: #60a5fa;">{low_count}</div>
                        <div class="label">Low / Info</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Open Ports Table -->
        <div class="card">
            <div class="card-title">Discovered Ports & Network Services ({len(report.open_ports)} Open)</div>
            <table>
                <thead>
                    <tr>
                        <th>Port / Proto</th>
                        <th>State</th>
                        <th>Service Identification</th>
                        <th>Latency</th>
                        <th>Service Banner / Response</th>
                    </tr>
                </thead>
                <tbody>
                    {port_rows}
                </tbody>
            </table>
        </div>

        {tls_html}

        <!-- Vulnerabilities & Mitigation -->
        <div class="card" style="margin-top: 1.5rem;">
            <div class="card-title">Vulnerability Assessment & Mitigation Guidelines ({len(report.vulnerabilities)} Identified)</div>
            {vuln_cards}
        </div>

        <footer>
            Generated automatically by <strong>VigilScan v1.0.0</strong> • Automated Network Security Posture & Vulnerability Assessment.
        </footer>
    </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
