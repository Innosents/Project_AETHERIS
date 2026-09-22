"""
Project AETHERIS - Network Scanner Infrastructure Adapter.
Implements NetworkScannerPort by encapsulating low-level discovery utilities
from aetheris.discovery.* (ICMP sweeps, ARP resolution, TCP socket scanning, banner grabbing).
"""

from typing import Any, Dict, List, Optional, Tuple

from aetheris.core.ports.discovery_engine_port import NetworkScannerPort
from aetheris.discovery.arp_scan import arp_scan as _arp_scan
from aetheris.discovery.banner_grab import grab_banner as _grab_banner
from aetheris.discovery.fingerprint import fingerprint_device as _fingerprint_device
from aetheris.discovery.icmp_scan import icmp_sweep as _icmp_sweep
from aetheris.discovery.port_scan import COMMON_PORTS as _COMMON_PORTS
from aetheris.discovery.port_scan import scan_ports_with_status as _scan_ports_with_status


class NetworkScannerAdapter(NetworkScannerPort):
    """
    Concrete adapter bridging NetworkScannerPort protocol contracts to local
    raw network discovery scripts and multi-threaded socket interrogators.
    """

    def icmp_sweep(self, target_ips: List[str]) -> List[str]:
        """Executes ICMP ping sweep against candidate IPs."""
        return _icmp_sweep(target_ips)

    def arp_scan(self, network_cidr: str) -> List[Dict[str, str]]:
        """Executes ARP discovery on local broadcast domain."""
        return _arp_scan(network_cidr)

    def scan_ports(self, ip: str, ports: Optional[List[int]] = None) -> Tuple[List[int], str]:
        """Probes TCP ports on target host, returning list of open ports and status."""
        target_ports = ports if ports is not None else _COMMON_PORTS
        return _scan_ports_with_status(ip, ports=target_ports)

    def grab_banner(self, ip: str, port: int, timeout: float = 1.0) -> str:
        """Retrieves raw service banner from open port via TCP socket."""
        return _grab_banner(ip, port, timeout=timeout)

    def fingerprint_device(
        self,
        ip: str,
        mac: str,
        open_ports: List[int],
        banners: Dict[int, str],
        services: List[str],
    ) -> Dict[str, Any]:
        """Synthesizes device DNA dictionary from multi-signal observation."""
        return _fingerprint_device(ip, mac, open_ports, banners, services)

    def get_common_ports(self) -> List[int]:
        """Returns baseline list of default discovery ports."""
        return list(_COMMON_PORTS)

