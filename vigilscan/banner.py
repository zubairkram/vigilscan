"""
Service banner grabbing and protocol fingerprinting.
Supports HTTP, SSH, FTP, SMTP, and generic socket listeners.
"""

import socket
import ssl
import re
from typing import Optional

# Maximum banner bytes to receive
MAX_BANNER_LEN = 1024


def clean_banner_text(data: bytes) -> str:
    """Sanitize raw banner bytes into a single printable line."""
    text = data.decode("utf-8", errors="replace").strip()
    # Normalize multiple whitespaces/newlines to single space
    cleaned = re.sub(r"[\r\n\t]+", " ", text)
    # Remove control characters
    cleaned = "".join(ch for ch in cleaned if ch.isprintable() or ch == " ")
    return cleaned[:160].strip()


def grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    """
    Attempt to grab service banner from an open port.
    Custom probes for HTTP/HTTPS, SSH, FTP, SMTP, and generic services.
    """
    # 1. HTTP/Web Ports Probe
    if port in (80, 8080, 8000, 8888, 5000, 3000):
        return grab_http_banner(host, port, use_tls=False, timeout=timeout)

    # 2. HTTPS/TLS Web Ports Probe
    if port in (443, 8443, 9443):
        return grab_http_banner(host, port, use_tls=True, timeout=timeout)

    # 3. Standard Text-Protocol Banner Grab (SSH, FTP, SMTP, POP3, IMAP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        
        # Some servers wait for client input before sending banner
        if port in (21, 22, 25, 110, 143):
            data = sock.recv(MAX_BANNER_LEN)
            if data:
                return clean_banner_text(data)

        # For Redis / generic services, try sending a harmless PING or newline
        if port == 6379:
            sock.sendall(b"PING\r\n")
            data = sock.recv(MAX_BANNER_LEN)
            if data:
                return clean_banner_text(data)

        # Fallback probe
        sock.sendall(b"\r\n\r\n")
        data = sock.recv(MAX_BANNER_LEN)
        if data:
            return clean_banner_text(data)

    except Exception:
        pass
    finally:
        sock.close()

    return ""


def grab_http_banner(host: str, port: int, use_tls: bool = False, timeout: float = 1.5) -> str:
    """
    Send a basic HTTP HEAD or GET request and extract Server / Status response.
    """
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        sock.connect((host, port))
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: VigilScan/1.0\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode("ascii"))
        
        resp = sock.recv(MAX_BANNER_LEN).decode("utf-8", errors="replace")
        lines = resp.split("\r\n")
        
        status_line = lines[0] if lines else ""
        server_line = ""
        for line in lines:
            if line.lower().startswith("server:"):
                server_line = line.strip()
                break

        if server_line:
            return f"{status_line} | {server_line}"
        elif status_line:
            return status_line
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return ""
