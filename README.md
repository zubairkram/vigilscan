# VigilScan 🛡️
### Lightweight Network Vulnerability Scanner & Security Posture Auditor
> **Directly Aligned with Certiport IT Specialist: Cybersecurity Exam Objectives**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-0%20(Standard%20Library)-success.svg)]()
[![Tests: 10 Passed](https://img.shields.io/badge/tests-10%2F10%20passed-brightgreen.svg)]()
[![Certiport Aligned](https://img.shields.io/badge/Certiport-IT%20Specialist-orange.svg)]()

**VigilScan** is a high-performance, modular network vulnerability scanner and cryptographic posture auditor written in pure Python with **zero external dependencies**. 

Engineered specifically around the **Certiport IT Specialist: Cybersecurity Certification Syllabus**, VigilScan transforms low-level network reconnaissance into executive-level risk intelligence, producing both machine-readable JSON data and an interactive, dark-themed HTML Security Dashboard.

---

## 📋 Certiport Exam Objectives Alignment

VigilScan was designed to demonstrate direct, practical implementation of the competencies outlined in the Certiport IT Specialist Cybersecurity standard:

| Certiport Exam Objective | Objective Description | VigilScan Implementation |
| :--- | :--- | :--- |
| **Domain 1.4: Encryption Methods & Applications** | Types of encryption, certificates, PKI, strong vs. weak algorithms, data in transit. | Performs deep SSL/TLS handshakes, validates CA trust, detects expired & self-signed certs, flags deprecated protocols (TLSv1.0/1.1), and flags weak cipher suites. |
| **Domain 2.1: TCP/IP Protocol Vulnerabilities** | TCP, UDP, HTTP, DNS, plain-text protocol risks. | Identifies risky cleartext protocols (Telnet, FTP, HTTP, NetBIOS, unencrypted DBs) and assesses cleartext data leakage. |
| **Domain 2.2: Network Addresses & Segmentation** | IPv4/IPv6, MAC, CIDR notation, public vs private. | Native CIDR parsing (`/24`, `/28`), IP resolution, and multi-host subnet scanning. |
| **Domain 4.1: Vulnerability Management** | Active reconnaissance, port scanning, service automation. | Multi-threaded TCP socket engine with sub-millisecond response timing and banner grabbing. |
| **Domain 4.2: Threat Intelligence & Reporting** | Common Vulnerabilities and Exposures (CVEs), CWE mappings, structured reports. | Matches exposed services against CWE classifications and CVSS v3.1 score estimates. |
| **Domain 4.3: Risk Management** | Vulnerability vs risk, ranking risks (Critical/High/Med/Low), mitigation strategies. | Dynamic scoring engine (0-100 Posture Score) with prioritized, step-by-step remediation guidance. |

---

## ✨ Key Features

- **Zero Third-Party Dependencies:** Runs anywhere Python 3.8+ is installed using only standard library modules (`socket`, `ssl`, `concurrent.futures`, `ipaddress`, `dataclasses`).
- **Concurrent High-Speed Engine:** Multi-threaded worker pool capable of scanning common ports in under 2 seconds.
- **Protocol Fingerprinting & Banner Grabbing:** Probes HTTP/HTTPS, SSH, FTP, SMTP, MySQL, and Redis services to capture service versions.
- **Deep SSL/TLS Cryptographic Audit:**
  - Validates certificate expiration dates and days remaining.
  - Detects self-signed certificates (untrusted root CA).
  - Inspects negotiated TLS protocol versions (flags SSLv3, TLS 1.0, and TLS 1.1).
  - Audits cipher suites for weak algorithms (RC4, 3DES, MD5, export ciphers).
- **Web Security Hardening Analysis:** Checks HTTP response headers for missing defenses:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (Clickjacking mitigation)
  - `X-Content-Type-Options` (MIME sniffing prevention)
  - Information disclosure via `Server` and `X-Powered-By` headers.
- **Risk Scoring & Executive Reporting:**
  - Categorizes findings into **CRITICAL**, **HIGH**, **MEDIUM**, and **LOW** risk tiers.
  - Computes a normalized **Security Posture Score (0–100)**.
  - Generates an **Executive HTML Security Report** featuring an SVG score gauge, open port maps, and remediation steps.
  - Exports structured JSON for SIEM/pipeline integration.
- **Offline Demonstration Mode (`--demo`):** Instant simulated enterprise audit showcasing full scanner capabilities without requiring an external target.

---

## 🏗️ Architecture & Project Structure

```text
vigilscan/
├── vigilscan/                  # Core Python Package
│   ├── __init__.py             # Package metadata
│   ├── models.py               # Typed dataclasses (PortResult, TlsAuditResult, Vulnerability)
│   ├── network.py              # Socket connection pool, CIDR expansion, port parser
│   ├── banner.py               # Protocol banner grabbing & service identification
│   ├── tls_audit.py            # SSL/TLS certificate & cryptographic auditor (Domain 1.4)
│   ├── web_audit.py            # HTTP security headers analyzer (Domain 2.1 & 4.1)
│   ├── risk_engine.py          # Vulnerability knowledgebase, CWE mapping & risk scoring
│   ├── reporter.py             # ANSI CLI formatter, JSON exporter & HTML report generator
│   └── core.py                 # Audit coordinator orchestrator
├── tests/
│   └── test_scanner.py         # Automated unit test suite (10 test cases)
├── reports/                    # Generated audit reports
│   ├── demo_audit_report.html  # Sample generated HTML security dashboard
│   └── demo_audit_report.json  # Sample generated JSON report
├── vigilscan.py                # Main CLI entrypoint
├── requirements.txt            # Zero dependencies specification
├── LICENSE                     # MIT License
└── README.md                   # Documentation
```

---

## 🚀 Quickstart & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/zubairkram/vigilscan.git
cd vigilscan
```

### 2. Verify Prerequisites
VigilScan requires **Python 3.8 or higher**. No `pip install` required!
```bash
python --version
```

### 3. Run the Instant Demo
Test all scanner functions, risk calculations, and report generation in simulation mode:
```bash
python vigilscan.py --demo
```
This generates `reports/demo_audit_report.html` and `reports/demo_audit_report.json`.

---

## 💻 Usage & CLI Examples

### Basic Scan (Top 25 Ports)
```bash
python vigilscan.py scanme.nmap.org
```

### Scan Specific Ports with Custom Thread Count
```bash
python vigilscan.py 192.168.1.1 -p 21,22,80,443,3389,8080 -t 30
```

### Scan a Port Range and Generate Custom Reports
```bash
python vigilscan.py example.com -p 1-1024 --html reports/example_audit.html --json reports/example_audit.json
```

### Scan Localhost
```bash
python vigilscan.py 127.0.0.1 -p quick
```

---

## 📊 Sample Output

### Terminal CLI Summary
```text
==================== SCAN SUMMARY ====================
Target:          corp-gateway.demo.local (192.168.10.45)
Scan Duration:   1.45s across 25 ports
Security Score:  0/100 (Risk Rating: CRITICAL)
Open Ports:      7
Vulnerabilities: 11
======================================================

OPEN PORTS & SERVICES:
PORT    STATE     SERVICE                     LATENCY     BANNER
---------------------------------------------------------------------------
21      open      FTP (File Transfer)         12.4ms      220 (vsFTPd 3.0.3) ready.
22      open      SSH (Secure Shell)          9.1ms       SSH-2.0-OpenSSH_8.2p1
23      open      Telnet (Unencrypted CLI)    15.2ms      Linux Telnet Service
80      open      HTTP (Web Traffic)          8.5ms       HTTP/1.1 200 OK | Apache/2.4.41
443     open      HTTPS (Encrypted Web)       14.8ms      HTTP/1.1 200 OK | Apache/2.4.41
3306    open      MySQL Database              18.0ms      5.7.33-0ubuntu0.18.04.1
3389    open      RDP (Remote Desktop)        22.3ms      MS Remote Desktop

SSL/TLS CRYPTOGRAPHIC STATUS (Certiport 1.4):
  Negotiated Protocol: TLSv1.1
  Cipher Suite:        ECDHE-RSA-AES256-SHA
  Certificate Subject: gateway.internal.corp
  Issuer:              gateway.internal.corp
  Expiration Date:     Jan 15 00:00:00 2025 GMT (-288 days remaining)
  [!] CRITICAL: Certificate is EXPIRED!

SECURITY FINDINGS & RISK RANKINGS (Certiport 4.3):
  [HIGH] Legacy Telnet Protocol Exposed (Port: 23, CVSS: 7.5)
    Classification: CWE-319 (Cleartext Transmission of Sensitive Information)
    Remediation:    Decommission Telnet. Migrate to SSHv2 with key-based authentication.
  [HIGH] Exposed MySQL Database Port (Port: 3306, CVSS: 7.5)
    Classification: CWE-284 (Improper Access Control)
    Remediation:    Bind MySQL to 127.0.0.1 or private VPC subnet.
  ...
[+] HTML Security Dashboard generated: reports/demo_audit_report.html
```

### Standalone HTML Dashboard Preview
The generated HTML dashboard includes:
- **Interactive SVG Circular Gauge:** Visualizes target posture score (0-100).
- **Executive Metric Cards:** Displays counts for Critical, High, Medium, and Low severity items.
- **Network Port Map:** Clean table with port status, protocol, service, latency, and banner info.
- **SSL/TLS Health Panel:** Certificate validity dates, issuer, subject, protocol version, and ciphers.
- **Detailed Remediation Cards:** Step-by-step hardening instructions and CWE classifications.

---

## 🧪 Running Unit Tests

The test suite validates socket parsing, banner cleaning, risk calculation algorithms, and report generation:

```bash
python -m unittest discover -s tests -v
```

Output:
```text
test_clean_banner (test_scanner.TestVigilScanBanner.test_clean_banner) ... ok
test_parse_cidr (test_scanner.TestVigilScanNetwork.test_parse_cidr) ... ok
test_parse_custom_range (test_scanner.TestVigilScanNetwork.test_parse_custom_range) ... ok
test_parse_invalid_port (test_scanner.TestVigilScanNetwork.test_parse_invalid_port) ... ok
test_parse_quick_ports (test_scanner.TestVigilScanNetwork.test_parse_quick_ports) ... ok
test_html_report_generation (test_scanner.TestVigilScanReporting.test_html_report_generation) ... ok
test_json_export (test_scanner.TestVigilScanReporting.test_json_export) ... ok
test_clean_target_score (test_scanner.TestVigilScanRiskEngine.test_clean_target_score) ... ok
test_expired_tls_risk (test_scanner.TestVigilScanRiskEngine.test_expired_tls_risk) ... ok
test_telnet_risk (test_scanner.TestVigilScanRiskEngine.test_telnet_risk) ... ok

----------------------------------------------------------------------
Ran 10 tests in 0.025s

OK
```

---

## 🗺️ Certiport Cybersecurity Portfolio Roadmap

This repository is **Project 1** in a multi-project cybersecurity portfolio aligned with the Certiport IT Specialist curriculum:

1. **Project 1 (This Repository): VigilScan** — Network Vulnerability Scanner & SSL/TLS Audit Engine *(Domains 1.4, 2.1, 2.2, 4.1, 4.2, 4.3)*
2. **Project 2: TraceGuard SIEM** — Lightweight Syslog Analyzer & MITRE ATT&CK Threat Detector *(Domains 1.2, 3.5, 5.1, 5.2)*
3. **Project 3: AuditArmor** — Endpoint Security & Host Hardening Compliance Auditor *(Domains 1.3, 3.1, 3.2, 3.3, 3.4)*
4. **Project 4: CryptoVault-CLI** — PKI, Data-at-Rest/Transit Encryption & File Integrity Verifier *(Domains 1.1, 1.4)*

---

## ⚖️ License & Ethical Usage

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

> **Ethical Disclaimer:** VigilScan is developed strictly for educational, defensive, and authorized penetration testing / auditing purposes. Never scan systems, networks, or hosts without explicit written permission from the owner.
