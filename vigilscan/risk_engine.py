"""
Vulnerability and Risk Assessment Engine.
Directly implements Certiport Domain 4: Vulnerability Assessment & Risk Management.
- 4.1 Vulnerability identification & mitigation
- 4.2 Threat intelligence & CVE/CWE categorization
- 4.3 Risk ranking (Critical, High, Medium, Low) & mitigation strategies
"""

from typing import List, Tuple
from vigilscan.models import PortResult, TlsAuditResult, HttpAuditResult, Vulnerability

# Knowledge base of known exposed port risks and CVE/CWE alignments
PORT_RISK_RULES = {
    21: {
        "title": "Unencrypted FTP Protocol Exposed",
        "severity": "MEDIUM",
        "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information)",
        "cvss": 5.3,
        "description": "Port 21 provides standard File Transfer Protocol (FTP) which transmits usernames, passwords, and data in unencrypted plaintext across the network.",
        "remediation": "Disable legacy FTP service and migrate to SFTP (over SSH) or FTPS with mandatory TLS encryption."
    },
    23: {
        "title": "Legacy Telnet Protocol Exposed (High Risk)",
        "severity": "HIGH",
        "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information)",
        "cvss": 7.5,
        "description": "Telnet operates without any cryptographic protection. All keystrokes, administrative credentials, and session data can be intercepted via passive sniffing or ARP poisoning.",
        "remediation": "Decommission the Telnet daemon immediately. Replace with Secure Shell (SSHv2) on port 22 with key-based authentication."
    },
    25: {
        "title": "Cleartext SMTP Mail Relay Exposed",
        "severity": "LOW",
        "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information)",
        "cvss": 3.7,
        "description": "Standard SMTP port 25 is accessible. If STARTTLS is not enforced or authentication is enabled in plaintext, credentials and emails may be exposed.",
        "remediation": "Enforce STARTTLS or migrate submission to SMTPS (port 465 or 587) and restrict open relay capabilities."
    },
    139: {
        "title": "NetBIOS Session Service Exposed",
        "severity": "MEDIUM",
        "cwe": "CWE-200 (Exposure of Sensitive Information)",
        "cvss": 5.8,
        "description": "NetBIOS port 139 is reachable from the network, which facilitates host enumeration, workgroup discovery, and null-session access.",
        "remediation": "Disable NetBIOS over TCP/IP in network adapter settings and restrict access through perimeter host firewalls."
    },
    445: {
        "title": "Exposed SMB (Server Message Block) Service",
        "severity": "HIGH",
        "cwe": "CWE-284 (Improper Access Control)",
        "cvss": 8.1,
        "description": "SMB port 445 is exposed. Publicly or broadly accessible SMB ports have historically been exploited by network worms (e.g. EternalBlue, WannaCry, NotPetya).",
        "remediation": "Block port 445 at the network firewall perimeter. Do not expose SMB directly to untrusted networks; require VPN for remote access."
    },
    3389: {
        "title": "Exposed Microsoft Remote Desktop (RDP)",
        "severity": "HIGH",
        "cwe": "CWE-306 (Missing Authentication for Critical Function)",
        "cvss": 7.3,
        "description": "Remote Desktop Protocol (RDP) is directly exposed. Exposed RDP endpoints are prime targets for automated credential stuffing, brute force, and exploits (e.g., BlueKeep).",
        "remediation": "Place RDP behind a secure VPN gateway or Remote Desktop Gateway with Multi-Factor Authentication (MFA). Enable Network Level Authentication (NLA)."
    },
    3306: {
        "title": "Exposed MySQL Database Port",
        "severity": "HIGH",
        "cwe": "CWE-284 (Improper Access Control)",
        "cvss": 7.5,
        "description": "MySQL database port 3306 is listening on an external interface. Database ports should never be exposed to public networks due to automated brute-force attacks.",
        "remediation": "Bind MySQL service to localhost (127.0.0.1) or private VPC subnet. Enforce strict firewall rules restricting access to trusted app servers."
    },
    5432: {
        "title": "Exposed PostgreSQL Database Port",
        "severity": "HIGH",
        "cwe": "CWE-284 (Improper Access Control)",
        "cvss": 7.5,
        "description": "PostgreSQL database port 5432 is accessible. External exposure risks dictionary attacks against database superusers (e.g. postgres).",
        "remediation": "Modify pg_hba.conf and postgresql.conf to listen only on internal interfaces or loopback, and mandate SSL connections."
    },
    5900: {
        "title": "Exposed VNC Remote Desktop Service",
        "severity": "MEDIUM",
        "cwe": "CWE-521 (Weak Password Requirements)",
        "cvss": 6.5,
        "description": "VNC (Virtual Network Computing) port 5900 is open. VNC passwords are traditionally truncated at 8 characters and traffic is unencrypted by default.",
        "remediation": "Tunnel VNC sessions through an encrypted SSH tunnel or VPN, and configure robust authentication controls."
    },
    6379: {
        "title": "Exposed Redis In-Memory Data Store",
        "severity": "HIGH",
        "cwe": "CWE-306 (Missing Authentication for Critical Function)",
        "cvss": 8.6,
        "description": "Redis port 6379 is reachable. Redis historically runs without authentication by default, allowing remote attackers to read all cached data or execute commands.",
        "remediation": "Set 'bind 127.0.0.1' in redis.conf, enable strong requirepass authentication, and block port 6379 at the firewall."
    },
    27017: {
        "title": "Exposed MongoDB NoSQL Database",
        "severity": "HIGH",
        "cwe": "CWE-284 (Improper Access Control)",
        "cvss": 8.2,
        "description": "MongoDB port 27017 is listening externally. Exposed MongoDB instances are frequent targets for automated ransomware and data leakages.",
        "remediation": "Enable authentication (auth = true), configure bindIp to 127.0.0.1, and verify network access control lists (ACLs)."
    },
}


def analyze_vulnerabilities(
    open_ports: List[PortResult],
    tls_audit: TlsAuditResult = None,
    http_audit: HttpAuditResult = None,
) -> Tuple[List[Vulnerability], int, str]:
    """
    Evaluate host security posture across network ports, SSL/TLS certificates,
    and HTTP security headers.
    Returns (vulnerabilities_list, security_score, risk_rating).
    """
    vulns: List[Vulnerability] = []
    open_port_numbers = {p.port for p in open_ports}

    # 1. Port-based exposure analysis
    for p in open_ports:
        port = p.port
        if port in PORT_RISK_RULES:
            rule = PORT_RISK_RULES[port]
            vulns.append(Vulnerability(
                vuln_id=f"VULN-PORT-{port}",
                title=rule["title"],
                severity=rule["severity"],
                cwe_id=rule["cwe"],
                port=port,
                description=rule["description"],
                remediation=rule["remediation"],
                cvss_estimate=rule["cvss"]
            ))

    # 2. Check for Plaintext HTTP without HTTPS
    if 80 in open_port_numbers and 443 not in open_port_numbers:
        vulns.append(Vulnerability(
            vuln_id="VULN-HTTP-NOPKI",
            title="Unencrypted HTTP Without HTTPS Support",
            severity="MEDIUM",
            cwe_id="CWE-319 (Cleartext Transmission of Sensitive Information)",
            port=80,
            description="The web server exposes unencrypted HTTP (port 80) without providing an encrypted HTTPS listener (port 443). All client traffic is vulnerable to interception.",
            remediation="Install an SSL/TLS certificate (e.g. Let's Encrypt) and enforce HTTPS with permanent 301 redirects.",
            cvss_estimate=5.3
        ))

    # 3. SSL/TLS Audit findings (Certiport Domain 1.4)
    if tls_audit and tls_audit.has_tls:
        if tls_audit.is_expired:
            vulns.append(Vulnerability(
                vuln_id="VULN-TLS-EXPIRED",
                title="Expired SSL/TLS Digital Certificate",
                severity="HIGH",
                cwe_id="CWE-298 (Improper Validation of Certificate Expiration)",
                port=443,
                description=f"The server presents an expired certificate that expired on {tls_audit.valid_to}. Web browsers will display security warnings, and user trust is compromised.",
                remediation="Renew and deploy an active certificate immediately from a recognized Certificate Authority (CA).",
                cvss_estimate=7.4
            ))
        elif tls_audit.is_expiring_soon:
            vulns.append(Vulnerability(
                vuln_id="VULN-TLS-EXPIRING",
                title=f"SSL/TLS Certificate Expiring Soon ({tls_audit.days_remaining} days)",
                severity="LOW",
                cwe_id="CWE-298 (Improper Validation of Certificate Expiration)",
                port=443,
                description=f"The server certificate will expire in {tls_audit.days_remaining} days on {tls_audit.valid_to}. Failure to renew will cause service disruption.",
                remediation="Schedule automated renewal via Certbot or PKI certificate management pipeline.",
                cvss_estimate=3.1
            ))

        if tls_audit.is_self_signed:
            vulns.append(Vulnerability(
                vuln_id="VULN-TLS-SELFSIGNED",
                title="Self-Signed SSL/TLS Certificate In Use",
                severity="MEDIUM",
                cwe_id="CWE-295 (Improper Certificate Validation)",
                port=443,
                description="The certificate issuer matches the subject, indicating a self-signed certificate not rooted in a trusted public PKI trust store.",
                remediation="Replace with a certificate signed by an established Certificate Authority (e.g. Let's Encrypt, DigiCert).",
                cvss_estimate=5.9
            ))

        for finding in tls_audit.findings:
            if "Deprecated TLS" in finding:
                vulns.append(Vulnerability(
                    vuln_id="VULN-TLS-DEPRECATED",
                    title="Deprecated Insecure TLS Protocol Version",
                    severity="HIGH",
                    cwe_id="CWE-326 (Inadequate Encryption Strength)",
                    port=443,
                    description=finding,
                    remediation="Disable legacy TLSv1.0 and TLSv1.1 on the server web server/load balancer. Enforce TLSv1.2 and TLSv1.3.",
                    cvss_estimate=7.5
                ))
            elif "Weak cipher" in finding:
                vulns.append(Vulnerability(
                    vuln_id="VULN-TLS-WEAKCIPHER",
                    title="Weak Cryptographic Cipher Suite Enabled",
                    severity="MEDIUM",
                    cwe_id="CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)",
                    port=443,
                    description=finding,
                    remediation="Update cipher suite configuration to prioritize forward-secret AEAD ciphers (e.g., ECDHE-RSA-AES128-GCM-SHA256).",
                    cvss_estimate=5.5
                ))

    # 4. HTTP Audit findings (Web security headers & info disclosure)
    if http_audit:
        if "Strict-Transport-Security" in http_audit.missing_headers:
            vulns.append(Vulnerability(
                vuln_id="VULN-HTTP-HSTS",
                title="Missing HTTP Strict Transport Security (HSTS) Header",
                severity="MEDIUM",
                cwe_id="CWE-319 (Cleartext Transmission of Sensitive Information)",
                port=80 if 80 in open_port_numbers else 443,
                description="The server does not send the Strict-Transport-Security header. Browsers may connect over plain HTTP on their first request, exposing users to SSL-stripping.",
                remediation="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in web server config.",
                cvss_estimate=4.3
            ))

        if "Content-Security-Policy" in http_audit.missing_headers:
            vulns.append(Vulnerability(
                vuln_id="VULN-HTTP-CSP",
                title="Missing Content-Security-Policy (CSP) Header",
                severity="LOW",
                cwe_id="CWE-79 (Improper Neutralization of Input During Web Page Generation)",
                port=80 if 80 in open_port_numbers else 443,
                description="A Content Security Policy header was not detected. CSP is a defense-in-depth mechanism that prevents unauthorized script execution and data theft.",
                remediation="Define and deploy a strict Content-Security-Policy header restricting script-src, object-src, and default-src directives.",
                cvss_estimate=3.8
            ))

        if "X-Frame-Options" in http_audit.missing_headers:
            vulns.append(Vulnerability(
                vuln_id="VULN-HTTP-CLICKJACK",
                title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                severity="LOW",
                cwe_id="CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)",
                port=80 if 80 in open_port_numbers else 443,
                description="The application does not specify X-Frame-Options or frame-ancestors, permitting third-party sites to frame the application for clickjacking attacks.",
                remediation="Add 'X-Frame-Options: SAMEORIGIN' or 'DENY' header to HTTP responses.",
                cvss_estimate=3.5
            ))

        if http_audit.server_header:
            vulns.append(Vulnerability(
                vuln_id="VULN-HTTP-BANNER",
                title="Web Server Version Information Disclosure",
                severity="LOW",
                cwe_id="CWE-200 (Exposure of Sensitive Information)",
                port=80 if 80 in open_port_numbers else 443,
                description=f"The web server exposes its exact software version in the Server header: '{http_audit.server_header}'. This assists attackers during reconnaissance.",
                remediation="Configure ServerTokens Prod (Apache) or server_tokens off (Nginx) to suppress detailed version banners.",
                cvss_estimate=2.6
            ))

    # 5. Security Posture Scoring (Base 100 with deductions)
    score = 100
    deductions = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 0
    }

    for v in vulns:
        score -= deductions.get(v.severity, 0)

    score = max(0, min(100, score))

    # Risk Rating categorization
    if score >= 90:
        rating = "LOW"
    elif score >= 75:
        rating = "MODERATE"
    elif score >= 50:
        rating = "HIGH"
    else:
        rating = "CRITICAL"

    # Sort vulnerabilities by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns.sort(key=lambda x: severity_order.get(x.severity, 5))

    return vulns, score, rating
