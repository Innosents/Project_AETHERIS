"""
Project AETHERIS - High-Performance Port Scanner & Common Ports Repository
Provides concurrent transport-layer port sweeps and status reporting conforming to PortScanPort.
"""

import socket
import concurrent.futures
from typing import List, Tuple, Dict, Any, Optional
from aetheris.core.ports.port_scan_port import (
    PortScanPort,
    PortProbeResult,
    PortScanSummary,
    COMMON_PORTS,
    _MappingCompatibleModel,
)


class PortScanner(PortScanPort):
    """Concurrent TCP port scanner implementation."""

    def scan_single_port(self, ip: str, port: int, timeout: float = 0.4) -> PortProbeResult:
        """Tests if a single TCP port is open."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                return PortProbeResult(port=port, is_open=(result == 0))
        except Exception:
            return PortProbeResult(port=port, is_open=False)

    def scan_ports(
        self,
        ip: str,
        ports: Optional[List[int]] = None,
        timeout: float = 0.4,
        max_workers: int = 50
    ) -> PortScanSummary:
        """Scans a list of target ports concurrently and returns open ports and scan status."""
        target_ports = ports if ports is not None else COMMON_PORTS
        open_ports: List[int] = []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(scan_single_port, ip, p, timeout): p for p in target_ports}
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if isinstance(res, (tuple, list)):
                        port_val, is_open = res[0], bool(res[1])
                    elif hasattr(res, "is_open"):
                        port_val, is_open = res.port, bool(res.is_open)
                    else:
                        port_val, is_open = futures[future], False
                    if is_open:
                        open_ports.append(port_val)
            return PortScanSummary(
                ip=ip,
                open_ports=sorted(open_ports),
                scanned_count=len(target_ports),
                status="completed"
            )
        except Exception:
            return PortScanSummary(
                ip=ip,
                open_ports=[],
                scanned_count=len(target_ports),
                status="failed"
            )


_default_scanner = PortScanner()


def scan_single_port(ip: str, port: int, timeout: float = 0.4) -> PortProbeResult:
    """Tests if a single TCP port is open. Backward-compatible wrapper."""
    return _default_scanner.scan_single_port(ip, port, timeout=timeout)


def scan_ports_with_status(
    ip: str,
    ports: List[int] = COMMON_PORTS,
    timeout: float = 0.4,
    max_workers: int = 50
) -> PortScanSummary:
    """Scans a list of ports concurrently and returns open ports and scan status. Backward-compatible wrapper."""
    return _default_scanner.scan_ports(ip, ports=ports, timeout=timeout, max_workers=max_workers)


__all__ = [
    "PortScanner",
    "PortScanPort",
    "PortProbeResult",
    "PortScanSummary",
    "COMMON_PORTS",
    "scan_single_port",
    "scan_ports_with_status",
    "_MappingCompatibleModel",
]