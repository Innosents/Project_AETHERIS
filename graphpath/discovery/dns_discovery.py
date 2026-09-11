"""
GraphPath Automated DNS Discovery & Service Resolution Module
Provides asynchronous Reverse DNS (PTR) sweeps and standard DNS SRV service discovery
for locating PBX servers, Domain Controllers, and infrastructure services.
"""

import socket
import ipaddress
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

STANDARD_SRV_SERVICES = [
    # VoIP & Telephony
    ("_sip._udp", "SIP VoIP PBX (UDP)"),
    ("_sip._tcp", "SIP VoIP PBX (TCP)"),
    ("_sips._tcp", "Secure SIP PBX (TLS)"),
    # Directory & Authentication
    ("_ldap._tcp", "Active Directory / LDAP Controller"),
    ("_kerberos._tcp", "Kerberos Authentication Server"),
    ("_kpasswd._tcp", "Kerberos Password Server"),
    # Management & Time Synchronization
    ("_ntp._udp", "Network Time Protocol (NTP) Server"),
    ("_syslog._udp", "Central Syslog Logging Server"),
]


class DnsDiscoveryEngine:
    """Performs non-intrusive DNS reverse PTR resolution and SRV service enumeration."""

    def __init__(self, dns_server: Optional[str] = None, timeout: float = 0.5):
        self.dns_server = dns_server
        self.timeout = timeout

    @staticmethod
    def get_system_dns_servers() -> List[str]:
        """Detects system configured DNS servers on Windows and Unix platforms."""
        servers = []
        try:
            import sys
            if sys.platform == "win32":
                import subprocess
                out = subprocess.check_output("nslookup - 127.0.0.1", shell=True, stderr=subprocess.DEVNULL, timeout=2).decode(errors="ignore")
        except Exception:
            pass
        return servers

    def resolve_ptr(self, ip_str: str) -> Optional[str]:
        """Resolves PTR record for a single IP address with a strict timeout."""
        # 1. If custom DNS server specified, query that DNS server directly
        if self.dns_server:
            try:
                import dns.resolver
                import dns.reversename
                res = dns.resolver.Resolver()
                res.nameservers = [self.dns_server]
                res.lifetime = self.timeout
                ptr_name = dns.reversename.from_address(ip_str)
                answers = res.resolve(ptr_name, "PTR")
                for r in answers:
                    h = str(r.target).rstrip(".")
                    if h:
                        return h
            except Exception:
                pass

            try:
                import struct
                rev_octets = ip_str.split(".")[::-1]
                ptr_name = f"{'.'.join(rev_octets)}.in-addr.arpa"
                query_id = 0x2130
                flags = 0x0100
                header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
                qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in ptr_name.split(".")) + b"\x00"
                question = qname_bytes + struct.pack("!HH", 12, 1)  # PTR, IN
                packet = header + question
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(packet, (self.dns_server, 53))
                resp, _ = sock.recvfrom(1024)
                sock.close()
                if len(resp) > 12:
                    offset = 12 + len(question)
                    if len(resp) > offset + 12:
                        curr = offset + 10
                        labels = []
                        while curr < len(resp):
                            length = resp[curr]
                            if length == 0:
                                break
                            if (length & 0xC0) == 0xC0:
                                p_curr = ((length & 0x3F) << 8) | resp[curr+1]
                                while p_curr < len(resp):
                                    p_len = resp[p_curr]
                                    if p_len == 0 or (p_len & 0xC0) == 0xC0:
                                        break
                                    labels.append(resp[p_curr+1:p_curr+1+p_len].decode("ascii", errors="ignore"))
                                    p_curr += 1 + p_len
                                break
                            labels.append(resp[curr+1:curr+1+length].decode("ascii", errors="ignore"))
                            curr += 1 + length
                        if labels:
                            return ".".join(labels)
            except Exception:
                pass

        # 2. Standard system resolver fallback
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            if hostname and hostname != ip_str:
                return hostname
        except (socket.herror, socket.gaierror, socket.timeout, Exception):
            pass
        return None

    def sweep_ptr_records(self, ips: List[str], max_workers: int = 20) -> Dict[str, str]:
        """
        Asynchronously sweeps a list of IP addresses to resolve hostnames via reverse DNS.
        Returns a mapping of {ip: hostname}.
        """
        results = {}
        if not ips:
            return results

        with ThreadPoolExecutor(max_workers=min(max_workers, len(ips) or 1)) as executor:
            future_to_ip = {executor.submit(self.resolve_ptr, ip): ip for ip in ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    hostname = future.result()
                    if hostname:
                        results[ip] = hostname
                except Exception:
                    pass

        return results

    def discover_srv_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        Queries standard DNS SRV records against a domain to uncover PBX servers,
        Domain Controllers, and central services without port scanning.
        """
        discovered = []
        if not domain or "." not in domain:
            return discovered

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            if self.dns_server:
                resolver.nameservers = [self.dns_server]

            for srv_prefix, service_label in STANDARD_SRV_SERVICES:
                qname = f"{srv_prefix}.{domain}"
                try:
                    answers = resolver.resolve(qname, "SRV")
                    for rdata in answers:
                        target_host = str(rdata.target).rstrip(".")
                        port = rdata.port
                        target_ip = None
                        try:
                            target_ip = socket.gethostbyname(target_host)
                        except Exception:
                            pass

                        discovered.append({
                            "service_name": srv_prefix,
                            "service_label": service_label,
                            "target_host": target_host,
                            "target_ip": target_ip,
                            "port": port,
                            "priority": rdata.priority,
                            "weight": rdata.weight,
                            "domain": domain
                        })
                except Exception:
                    continue
        except ImportError:
            pass

        return discovered


def run_dns_subnet_discovery(network_cidr: str) -> Dict[str, Any]:
    """Helper entry point for subnet-wide DNS enumeration."""
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
    except Exception:
        return {"ptr_records": {}, "srv_services": []}

    engine = DnsDiscoveryEngine()
    ptr_map = engine.sweep_ptr_records(hosts)

    srv_results = []
    discovered_domains = set()
    for hostname in ptr_map.values():
        parts = hostname.split(".", 1)
        if len(parts) > 1 and "." in parts[1]:
            discovered_domains.add(parts[1])

    for dom in discovered_domains:
        srv_results.extend(engine.discover_srv_records(dom))

    return {
        "ptr_records": ptr_map,
        "srv_services": srv_results
    }
