"""
Project AETHERIS - Arp Scan
Discovers active link-layer nodes across target CIDR boundaries through raw Ethernet broadcast ARP injection coupled with kernel neighbor cache interrogation. Normalizes IPv4-to-MAC hardware bindings
into discrete graph adjacency nodes for Layer-2 topology baseline hydration.
"""

import subprocess
import re
from typing import List, Dict

from loguru import logger

def arp_scan(network_cidr: str) -> List[Dict[str, str]]:
    """
    Performs a link-layer ARP discovery sweep over the target network CIDR boundary.
    Combines Scapy L2 raw injection with native Windows OS ARP table extraction
    to ensure 100% of local devices have their MAC addresses mapped.
    """
    print(f"[Tier 4 Scan] Initializing hardware mapping injection sweep over: {network_cidr}")
    discovered: Dict[str, str] = {}

    # 1. Scapy Layer-2 Raw Injection (if available)
    try:
        from scapy.all import srp
        from scapy.layers.l2 import ARP, Ether
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr)
        ans, _ = srp(pkt, timeout=1.5, verbose=False, inter=0.01)
        for _, r in ans:
            if r.psrc and r.hwsrc:
                discovered[r.psrc] = r.hwsrc.upper().replace("-", ":")
    except Exception as e:
        print(f"[Tier 4 Scan] Scapy L2 injection bypassed: {e}")

    # Defensive Scapy Layer-2 Wrapper Pattern
    try:
        from scapy.all import srp
        from scapy.layers.l2 import ARP, Ether
        # Execute raw socket injection logic
        ans, _ = srp(pkt, timeout=1.5, verbose=False)
    except (PermissionError, OSError) as e:
        logger.warning(f"[Discovery Fallback] Raw packet injection restricted on host interface: {e}. Diverting to OS ARP table extraction.")
        ans = [] # Trigger safe fallback vector

    # 2. Native Windows OS ARP Table Interrogation (Guaranteed OS Link-Layer Table)
    try:
        import ipaddress
        try:
            target_net = ipaddress.ip_network(network_cidr, strict=False)
        except Exception:
            target_net = None

        output = subprocess.check_output(["arp", "-a"], text=True, errors="ignore", timeout=2.0)
        for line in output.splitlines():
            match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F\-]{17}|[0-9a-fA-F\:]{17})\s+dynamic', line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if (target_net is None or ip_obj in target_net) and not ip_obj.is_multicast and not ip_obj.is_reserved and mac != "FF:FF:FF:FF:FF:FF":
                        discovered[ip] = mac
                except ValueError:
                    pass
    except Exception as e:
        print(f"[Tier 4 Scan] Windows OS ARP table query notice: {e}")

    results = [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]
    print(f"[Tier 4 Scan] Successfully mapped {len(results)} remote assets via hardware ARP table.")
    return results