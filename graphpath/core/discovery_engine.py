"""
Project AETHERIS - Core Discovery Engine
Coordinates active matrix sweeps, ARP mapping, multi-variance stealth probes,
and adaptive deep protocol interrogation.
"""

import os
import sys
import time
import threading
from typing import Dict, Any, Optional, List

from graphpath.discovery.icmp_scan import icmp_sweep
from graphpath.discovery.port_scan import scan_ports_with_status, COMMON_PORTS
from graphpath.discovery.banner_grab import grab_banner
from graphpath.discovery.fingerprint import fingerprint_device
from graphpath.core.device_classifier import DeviceClassifier


class DiscoveryEngine:
    def __init__(self, graph: Any, allow_industrial_probing: bool = False, policy_mode: str = "heuristic") -> None:
        self.graph = graph
        self.policy_mode = policy_mode
        if not allow_industrial_probing:
            allow_industrial_probing = (
                os.environ.get("GRAPHPATH_ALLOW_INDUSTRIAL") == "1"
                or os.environ.get("GRAPHPATH_ENVIRONMENT") == "industrial_vlan_lab"
            )
        self.allow_industrial_probing = allow_industrial_probing
        self.classifier = DeviceClassifier()
        self._lock = threading.Lock()
        self.discovered_vlans: Dict[int, str] = {}
        self.has_pcap = True

    def register_discovered_node(self, node_ip: str, telemetry: Dict[str, Any]) -> None:
        """Mutates graph state safely within a transactional boundary."""
        if not node_ip or node_ip in ("0.0.0.0", "255.255.255.255"):
            return

        try:
            import ipaddress
            from graphpath.core.scope_guard import get_scope_guard
            ip_obj = ipaddress.ip_address(node_ip)
            if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback:
                return
            scope_guard = get_scope_guard()
            permitted, _ = scope_guard.is_permitted(node_ip)
            if not permitted and not ip_obj.is_private:
                return
        except ValueError:
            pass

        with self._lock:
            with self.graph.batch_transaction():
                self.graph.add_node(node_ip, telemetry)

    def run_basic_sweep(self, network_cidr: str = "192.168.1.0/24", ports: Optional[List[int]] = None) -> None:
        """Active concurrent network matrix sweep."""
        print(f"[Tier 4] Sweeping local topology context: {network_cidr}")
        import ipaddress
        from graphpath.core.scope_guard import get_scope_guard
        scope_guard = get_scope_guard()

        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        except ValueError:
            base_net = network_cidr.rsplit(".", 1)[0]
            ips = [f"{base_net}.{i}" for i in range(1, 254)]

        ips = [ip for ip in ips if scope_guard.is_permitted(ip)[0]]
        if not ips:
            print(f"[Tier 4] Target network {network_cidr} has 0 authorized target IPs.")
            return

        from graphpath.discovery.arp_scan import arp_scan
        arp_nodes = arp_scan(network_cidr)
        arp_ips = {node["ip"]: node["mac"] for node in arp_nodes}

        reachable = icmp_sweep(ips)
        active_ips = set(reachable) | set(arp_ips.keys())

        self.register_discovered_node(network_cidr, {"type": "subnet", "vendor": "Network Boundary"})

        from concurrent.futures import ThreadPoolExecutor, as_completed
        from graphpath.core.dip_manager import DeviceIdentityProfileManager
        from graphpath.core.security_auditor import SecurityAuditor
        dip_manager = DeviceIdentityProfileManager()

        def _fingerprint_and_register(ip_addr: str):
            allowed, _ = scope_guard.is_permitted(ip_addr)
            if not allowed:
                return

            mac_addr = arp_ips.get(ip_addr, "")
            target_ports = COMMON_PORTS if ports is None else ports
            open_ports, scan_status = scan_ports_with_status(ip_addr, ports=target_ports)
            banners = {p: grab_banner(ip_addr, p) for p in open_ports}
            hostname = ""

            # Adaptive Prober / Deep Inspection
            deep_telemetry = {}
            try:
                from graphpath.core.adaptive_orchestrator import AdaptiveDiscoveryOrchestrator, EvidenceVector
                ev = EvidenceVector(ip=ip_addr, mac=mac_addr, open_ports=open_ports, banners=banners, subnet_cidr=network_cidr)
                orchestrator = AdaptiveDiscoveryOrchestrator()
                deep_telemetry = orchestrator.execute_adaptive_sweep(ev, timeout=0.4)
                if deep_telemetry.get("banners"):
                    banners.update(deep_telemetry["banners"])
                if deep_telemetry.get("hostname"):
                    hostname = deep_telemetry["hostname"]
            except Exception:
                pass

            services = []
            if 80 in open_ports or 443 in open_ports: services.append("http")
            if 22 in open_ports: services.append("ssh")
            if 5060 in open_ports: services.append("sip")

            device_dna = fingerprint_device(ip_addr, mac_addr, open_ports, banners, services)
            device_dna["hostname"] = hostname
            classified = self.classifier.classify(device_dna)

            if deep_telemetry:
                for attr in ["domain", "os_version", "serial_number", "firmware"]:
                    if deep_telemetry.get(attr):
                        classified[attr] = deep_telemetry[attr]
                if deep_telemetry.get("type") and deep_telemetry["type"] != "unknown":
                    classified["type"] = deep_telemetry["type"]

            advisory = SecurityAuditor.audit_device(classified)
            classified["security_advisories"] = advisory.get("findings", [])
            classified["risk_level"] = advisory.get("risk_level", "NONE")
            classified["risk_score"] = advisory.get("risk_score", 0)
            classified["ip"] = ip_addr
            if mac_addr:
                classified["mac"] = mac_addr

            if classified.get("type") and classified.get("type") not in ("unknown", "subnet"):
                dip_manager.learn_device(ip_addr, mac_addr, hostname, classified, network_cidr, "active_sweep")

            self.register_discovered_node(ip_addr, classified)
            with self._lock:
                self.graph.add_edge(network_cidr, ip_addr, {"layer": 3, "method": "tier4_sweep"})

        with ThreadPoolExecutor(max_workers=3) as executor:
            list(executor.map(_fingerprint_and_register, list(active_ips)))

    def run_passive(self, execution_timeout: float = 2.0) -> None:
        """Placeholder for passive monitoring."""
        pass

    def run_credentialed(self) -> None:
        """Placeholder for SNMP/SSH crawling."""
        pass

    def run_adaptive(self) -> None:
        """Placeholder for VLAN adjustments."""
        pass