"""
Unit test suite for VigilScan.
Validates port range parsing, CIDR expansion, banner sanitization,
risk assessment engine, and report exporters.
"""

import unittest
import os
import tempfile
import json

from vigilscan.network import parse_port_range, parse_network_targets
from vigilscan.banner import clean_banner_text
from vigilscan.models import PortResult, TlsAuditResult, HttpAuditResult, HostScanReport
from vigilscan.risk_engine import analyze_vulnerabilities
from vigilscan.reporter import generate_html_report, export_json


class TestVigilScanNetwork(unittest.TestCase):
    def test_parse_quick_ports(self):
        ports = parse_port_range("quick")
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(22, ports)
        self.assertEqual(len(ports), 25)

    def test_parse_custom_range(self):
        ports = parse_port_range("80, 443, 8000-8003")
        expected = [80, 443, 8000, 8001, 8002, 8003]
        self.assertEqual(ports, expected)

    def test_parse_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_port_range("99999")
        with self.assertRaises(ValueError):
            parse_port_range("8000-7000")

    def test_parse_cidr(self):
        targets = parse_network_targets("192.168.1.0/30")
        self.assertEqual(len(targets), 2)  # .1 and .2 usable hosts


class TestVigilScanBanner(unittest.TestCase):
    def test_clean_banner(self):
        raw = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n\x00"
        cleaned = clean_banner_text(raw)
        self.assertEqual(cleaned, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")


class TestVigilScanRiskEngine(unittest.TestCase):
    def test_telnet_risk(self):
        ports = [PortResult(port=23, state="open", service_name="Telnet")]
        vulns, score, rating = analyze_vulnerabilities(ports)
        
        # Telnet should trigger HIGH severity deduction (-15)
        self.assertEqual(score, 85)
        self.assertEqual(rating, "MODERATE")
        self.assertTrue(any(v.port == 23 and v.severity == "HIGH" for v in vulns))

    def test_expired_tls_risk(self):
        ports = [PortResult(port=443, state="open", service_name="HTTPS")]
        tls = TlsAuditResult(has_tls=True, is_expired=True, valid_to="Jan 01 2024")
        vulns, score, rating = analyze_vulnerabilities(ports, tls_audit=tls)
        
        self.assertTrue(any("Expired SSL/TLS" in v.title for v in vulns))
        self.assertLess(score, 100)

    def test_clean_target_score(self):
        # Port 80 and 443 with valid TLS and all headers
        ports = [
            PortResult(port=80, state="open"),
            PortResult(port=443, state="open")
        ]
        tls = TlsAuditResult(has_tls=True, is_expired=False, tls_version="TLSv1.3")
        http = HttpAuditResult(status_code=200, missing_headers=[])
        vulns, score, rating = analyze_vulnerabilities(ports, tls_audit=tls, http_audit=http)
        
        self.assertEqual(score, 100)
        self.assertEqual(rating, "LOW")
        self.assertEqual(len(vulns), 0)


class TestVigilScanReporting(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.report = HostScanReport(
            target="test.example.com",
            ip_address="93.184.216.34",
            duration_seconds=0.85,
            total_ports_scanned=10,
            open_ports=[PortResult(port=443, protocol="tcp", state="open", service_name="HTTPS")],
            security_score=92,
            risk_rating="LOW"
        )

    def test_json_export(self):
        json_path = os.path.join(self.test_dir, "test_report.json")
        export_json(self.report, json_path)
        
        self.assertTrue(os.path.exists(json_path))
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["target"], "test.example.com")
        self.assertEqual(data["security_score"], 92)

    def test_html_report_generation(self):
        html_path = os.path.join(self.test_dir, "test_report.html")
        generate_html_report(self.report, html_path)
        
        self.assertTrue(os.path.exists(html_path))
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("VigilScan Security Audit", html)
        self.assertIn("test.example.com", html)
        self.assertIn("92", html)


if __name__ == "__main__":
    unittest.main()
