"""
Network discovery, socket scanning, and port parsing module.
Covers Certiport Domain 2: Basic Network Security Concepts (TCP/UDP, Ports, CIDR, IP).
"""

import socket
import ipaddress
import time
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from vigilscan.models import PortResult

# Standard Well-Known Services mapping
WELL_KNOWN_SERVICES = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted CLI)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name System)",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP (Trivial FTP)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Post Office Protocol)",
    123: "NTP (Network Time)",
    135: "MS-RPC",
    139: "NetBIOS Session Service",
    143: "IMAP (Mail Access)",
    161: "SNMP (Network Management)",
    389: "LDAP (Directory Service)",
    443: "HTTPS (Encrypted Web)",
    445: "SMB (Server Message Block)",
    465: "SMTPS (Secure Mail)",
    587: "SMTP Submission",
    636: "LDAPS (Secure LDAP)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "MS SQL Server",
    1521: "Oracle Database",
    2049: "NFS (Network File System)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Desktop",
    6379: "Redis Cache Store",
    8000: "HTTP Alt / Dev Server",
    8080: "HTTP Proxy / Alt Web",
    8443: "HTTPS Alt / Admin Web",
    8888: "HTTP Alt Web",
    9200: "Elasticsearch REST API",
    27017: "MongoDB Database",
}

TOP_25_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 
    8000, 8080, 8443, 27017
]


def resolve_target(target: str) -> Tuple[str, str]:
    """
    Resolve a hostname or IP string to (target_name, canonical_ip).
    Raises socket.gaierror on invalid hostname.
    """
    target = target.strip()
    # Strip protocols if provided by accident (e.g., http://)
    if "://" in target:
        target = target.split("://")[1].split("/")[0].split(":")[0]

    ip = socket.gethostbyname(target)
    return target, ip


def parse_port_range(port_spec: str) -> List[int]:
    """
    Parse port specification strings like '80,443,8000-8010' or 'common' or 'quick'.
    Returns a sorted list of unique integers.
    """
    port_spec = port_spec.strip().lower()

    if port_spec in ("quick", "top25"):
        return sorted(list(TOP_25_PORTS))

    if port_spec in ("all", "1-65535"):
        return list(range(1, 65536))

    ports = set()
    parts = port_spec.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s.strip()), int(end_s.strip())
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Port out of range 1-65535: {p}")
            ports.add(p)

    return sorted(list(ports))


def parse_network_targets(target_spec: str) -> List[str]:
    """
    Parse a single target or CIDR block (e.g., '192.168.1.0/30' or 'scanme.nmap.org').
    """
    target_spec = target_spec.strip()
    if "/" in target_spec:
        try:
            net = ipaddress.ip_network(target_spec, strict=False)
            # Exclude network/broadcast for standard subnets
            hosts = [str(ip) for ip in net.hosts()]
            return hosts if hosts else [str(net.network_address)]
        except ValueError:
            pass
    return [target_spec]


def probe_tcp_port(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    """
    Perform a single TCP connect probe to determine port state and latency.
    """
    result = PortResult(
        port=port,
        protocol="tcp",
        state="closed",
        service_name=WELL_KNOWN_SERVICES.get(port, "unknown"),
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start_time = time.perf_counter()

    try:
        err = sock.connect_ex((ip, port))
        latency = (time.perf_counter() - start_time) * 1000.0
        result.response_time_ms = round(latency, 2)

        if err == 0:
            result.state = "open"
        else:
            result.state = "closed"
    except socket.timeout:
        result.state = "filtered"
    except (OSError, socket.error):
        result.state = "closed"
    finally:
        sock.close()

    return result


def scan_ports(
    ip: str, 
    ports: List[int], 
    threads: int = 50, 
    timeout: float = 1.0,
    callback=None
) -> List[PortResult]:
    """
    Scan a list of ports concurrently using ThreadPoolExecutor.
    Returns only open or filtered ports (ignoring closed ports to keep results clean).
    """
    open_results: List[PortResult] = []
    
    with ThreadPoolExecutor(max_workers=min(threads, len(ports) or 1)) as executor:
        future_map = {
            executor.submit(probe_tcp_port, ip, port, timeout): port 
            for port in ports
        }
        
        for future in as_completed(future_map):
            res = future.result()
            if callback:
                callback(res)
            if res.state == "open":
                open_results.append(res)

    open_results.sort(key=lambda r: r.port)
    return open_results
