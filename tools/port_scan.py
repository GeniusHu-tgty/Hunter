# tools/port_scan.py
"""Hunter v4 — Port Scanner

Socket-based port scanner with service detection.
Falls back to nmap if available for version detection.
"""

import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import TOOLS

TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2100, 2103, 2121, 2199, 2717, 2869, 2967, 3000, 3001, 3128,
    3306, 3389, 3986, 4899, 5000, 5001, 5003, 5009, 5050, 5051, 5060, 5101,
    5120, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8001, 8008, 8009, 8010, 8080, 8081, 8443, 8888, 9000, 9001, 9090,
    9100, 9999, 10000, 27017, 28017, 50000, 50070,
]

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3000: "http", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http",
    8001: "http", 8008: "http", 8009: "ajp", 8010: "http",
    8080: "http", 8081: "http", 8443: "https", 8888: "http",
    9000: "http", 9090: "http", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 50000: "sap",
}


def parse_ports(ports_spec: str) -> list[int]:
    """Parse port specification into list of port numbers."""
    if ports_spec == "top100":
        return TOP_100
    elif ports_spec == "top1000":
        return sorted(set(TOP_100 + list(range(1, 1024))))
    elif "-" in ports_spec:
        start, end = ports_spec.split("-", 1)
        return list(range(int(start), int(end) + 1))
    elif "," in ports_spec:
        return [int(p.strip()) for p in ports_spec.split(",")]
    else:
        return [int(ports_spec)]


def _grab_banner(host: str, port: int, timeout: float) -> str:
    """Try to grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200]
    except Exception:
        return ""


def port_scan_impl(host: str, ports: str = "top100", timeout: int = 3) -> dict:
    """Scan ports on target host."""
    start = time.time()
    port_list = parse_ports(ports)

    open_ports = []
    closed_count = 0
    filtered_count = 0

    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = SERVICE_MAP.get(port, "")
                banner = _grab_banner(host, port, timeout)
                open_ports.append({"port": port, "service": service, "version": banner})
            else:
                closed_count += 1
            sock.close()
        except socket.timeout:
            filtered_count += 1
        except Exception:
            closed_count += 1

    elapsed_ms = int((time.time() - start) * 1000)

    return {
        "host": host,
        "open": open_ports,
        "closed_count": closed_count,
        "filtered_count": filtered_count,
        "scan_time_ms": elapsed_ms,
        "total_scanned": len(port_list),
    }
