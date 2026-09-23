"""
Project AETHERIS - Linux Crawler
Authenticates to remote Linux endpoints over secure shell sessions to extract authoritative kernel releases, memory topologies, and routing tables via non-intrusive commands. Translates host-level 
system telemetry into structured node attributes and updates the centralized topological graph store.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional, List, Union

try:
    import paramiko
except ImportError:
    paramiko = None

from aetheris.core.ports.linux_crawler_port import (
    LinuxCrawlerPort,
    LinuxHostTelemetry,
    LinuxArpNeighbor,
    LinuxCrawlerRunSummary,
    _MappingCompatibleModel,
)

try:
    from aetheris.topology.graph_store import GraphStore
except ImportError:
    GraphStore = Any


class LinuxEndpointCrawler(LinuxCrawlerPort):
    """Hexagonal Adapter coordinator for SSH-based remote Linux endpoint profiling."""

    def __init__(self, graph_store: Optional[GraphStore] = None, timeout: float = 1.5) -> None:
        self.graph = graph_store
        self.timeout = timeout

    def _execute_command(self, client: Any, command: str) -> str:
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            return stdout.read().decode(errors="ignore").strip()
        except Exception:
            return ""

    @staticmethod
    def parse_os_release(raw_output: str) -> str:
        """Extracts pretty distribution name or returns raw kernel string."""
        if not raw_output:
            return "Linux"
        pretty_name = re.search(r'PRETTY_NAME="([^"]+)"', raw_output)
        if pretty_name:
            return pretty_name.group(1).strip()
        return raw_output.strip() or "Linux"

    @staticmethod
    def parse_mem_info(raw_output: str) -> Optional[str]:
        """Extracts total system RAM in megabytes from free -m output."""
        if not raw_output:
            return None
        for line in raw_output.splitlines():
            if "Mem:" in line or "Mem" in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
        return None

    @staticmethod
    def parse_listening_services(raw_output: str) -> Optional[str]:
        """Extracts listening network services from ss -tulpn output."""
        if not raw_output:
            return None
        services = []
        for line in raw_output.splitlines():
            if not line.strip():
                continue
            match = re.search(r'(:[0-9]+)\s+.*users:\(\("([^"]+)"', line)
            if match:
                port = match.group(1).replace(':', '')
                app = match.group(2)
                services.append(f"{app}:{port}")
        if services:
            return ", ".join(sorted(list(set(services))))
        return None

    @staticmethod
    def parse_arp_cache(raw_output: str) -> List[LinuxArpNeighbor]:
        """Extracts neighboring IP-to-MAC associations from arp -a output."""
        if not raw_output:
            return []
        neighbors: List[LinuxArpNeighbor] = []
        for line in raw_output.splitlines():
            match = re.search(r'\(([\d\.]+)\) at ([0-9a-fA-F:]+)(?:.*on\s+([^\s]+))?', line)
            if match:
                neighbor_ip = match.group(1)
                neighbor_mac = match.group(2).upper()
                iface = match.group(3) if match.group(3) else None
                if neighbor_mac != "00:00:00:00:00:00":
                    neighbors.append(LinuxArpNeighbor(
                        ip=neighbor_ip,
                        mac=neighbor_mac,
                        interface=iface
                    ))
        return neighbors

    def crawl_linux_server(self, ip: str, credentials: Dict[str, str]) -> Optional[LinuxHostTelemetry]:
        """
        Connects over SSH, executes non-intrusive discovery commands, and returns
        typed LinuxHostTelemetry while updating graph store if attached.
        """
        if paramiko is None:
            print(f"[Tier 2 Linux] Paramiko SSH library unavailable for {ip}")
            return None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        username = credentials.get("username", "admin")
        password = credentials.get("password", "")

        try:
            print(f"[Tier 2 Linux] Attempting SSH authentication to {ip}...")
            client.connect(
                hostname=ip,
                port=22,
                username=username,
                password=password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            print(f"[+] Authenticated to Linux server: {ip}")

            # 1. OS & Distribution
            os_release_raw = self._execute_command(client, "cat /etc/os-release")
            os_version = self.parse_os_release(os_release_raw)
            if os_version == "Linux" or not os_release_raw:
                uname_raw = self._execute_command(client, "uname -srm")
                if uname_raw:
                    os_version = uname_raw

            # 2. Hardware / Memory
            mem_raw = self._execute_command(client, "free -m | grep Mem")
            total_ram_mb = self.parse_mem_info(mem_raw)

            # 3. Running Services (Listening Ports)
            ss_raw = self._execute_command(client, "ss -tulpn | grep LISTEN")
            running_services = self.parse_listening_services(ss_raw)

            # 4. Expand Topology (ARP cache)
            arp_raw = self._execute_command(client, "arp -a")
            arp_neighbors = self.parse_arp_cache(arp_raw)

            if self.graph:
                for neighbor in arp_neighbors:
                    self.graph.add_node(neighbor.ip, {
                        "ip": neighbor.ip,
                        "mac": neighbor.mac,
                        "discovery_method": "linux_arp_cache"
                    })
                    self.graph.add_edge(ip, neighbor.ip, {
                        "layer": 3,
                        "method": "linux_arp_cache"
                    })

            telemetry = LinuxHostTelemetry(
                ip=ip,
                type="server",
                os="Linux",
                os_version=os_version,
                total_ram_mb=total_ram_mb,
                running_services=running_services,
                arp_neighbors=arp_neighbors,
                discovery_method="tier_2_linux_ssh"
            )

            if self.graph:
                self.graph.add_node(ip, dict(telemetry))

            print(f" [✓] Profiled Linux Server {ip}: {telemetry.os_version}")
            if telemetry.running_services:
                print(f"     Services: {telemetry.running_services}")

            return telemetry

        except Exception as e:
            print(f"[Tier 2 Linux] Failed to crawl {ip}: {e}")
            return None
        finally:
            try:
                client.close()
            except Exception:
                pass


def run_linux_crawler(graph_store: Optional[GraphStore], targets: list, credentials: Dict[str, str]) -> List[LinuxHostTelemetry]:
    """Module-level batch execution helper maintaining backward compatibility."""
    crawler = LinuxEndpointCrawler(graph_store)
    results = []
    for ip in targets:
        res = crawler.crawl_linux_server(ip, credentials)
        if res:
            results.append(res)
    return results


__all__ = [
    "LinuxEndpointCrawler",
    "LinuxCrawlerPort",
    "LinuxHostTelemetry",
    "LinuxArpNeighbor",
    "LinuxCrawlerRunSummary",
    "run_linux_crawler",
    "_MappingCompatibleModel",
]
