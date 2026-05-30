# tools/dns_tool.py
"""Hunter v4 — DNS Resolver

DNS query tool supporting A, AAAA, MX, TXT, NS, CNAME, SOA, SRV records.
"""

import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def dns_impl(domain: str, record_type: str = "ANY") -> dict:
    """Resolve DNS records for a domain."""
    records = []

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        types_to_query = [record_type] if record_type != "ANY" else [
            "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"
        ]

        for rtype in types_to_query:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    record = {"type": rtype, "value": str(rdata), "ttl": answers.rrset.ttl}
                    if rtype == "MX":
                        record["priority"] = rdata.preference
                        record["value"] = str(rdata.exchange)
                    records.append(record)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue

    except ImportError:
        try:
            ip = socket.gethostbyname(domain)
            records.append({"type": "A", "value": ip, "ttl": 0})
        except socket.gaierror as e:
            return {"domain": domain, "records": [], "error": str(e)}

        try:
            result = subprocess.run(["dig", "+short", "MX", domain],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            records.append({"type": "MX", "value": parts[1], "priority": int(parts[0]), "ttl": 0})
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return {"domain": domain, "records": records}
