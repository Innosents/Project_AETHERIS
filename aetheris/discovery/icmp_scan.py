"""
Project AETHERIS - Icmp Scan
Executes concurrent network-layer reachability sweeps across target IP spaces utilizing a bounded thread pool executing native ICMP echo commands. Identifies active subnet endpoints with millisecond timeouts to establish the foundational live-node vector for subsequent deep probing tiers.
"""

from __future__ import annotations

import sys
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from aetheris.core.ports.icmp_scan_port import (
    IcmpScanPort,
    IcmpHostResult,
    IcmpSweepSummary,
    _MappingCompatibleModel,
)


def ping_host_native(ip: str) -> bool:
    """
    Executes an OS-validated native ICMP echo lookup block.
    Cross-platform safe configuration for both Windows and Unix execution targets.
    """
    try:
        # Determine host system OS matrix dynamically
        if sys.platform.startswith("win"):
            # Windows: -n (count), -w (timeout in ms)
            cmd = ["ping", "-n", "1", "-w", "300", ip]
        else:
            # Unix/Linux: -c (count), -W (timeout in seconds)
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return proc.returncode == 0
    except Exception:
        return False


def icmp_sweep(hosts: List[str], max_workers: int = 60) -> List[str]:
    """Executes an optimized high-density network sweep using native OS threads."""
    reachable_ips = []
    
    # Maximize thread pool utilization for fast subnet discoveries
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(ping_host_native, hosts)
        for ip, is_active in zip(hosts, results):
            if is_active:
                reachable_ips.append(ip)
                print(f"[Tier 4 Diagnostics] Discovered live active subnet node: {ip}")
                
    return reachable_ips


class IcmpScanner(IcmpScanPort):
    """Hexagonal Adapter coordinator for ICMP reachability operations."""

    def ping_host(self, ip: str, timeout_ms: int = 300) -> IcmpHostResult:
        """
        Executes an ICMP echo check against target IP returning typed IcmpHostResult.
        Cross-platform safe for Windows (-w ms) and POSIX (-W sec).
        """
        try:
            if sys.platform.startswith("win"):
                cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
            else:
                timeout_sec = str(max(1, int(round(timeout_ms / 1000.0))))
                cmd = ["ping", "-c", "1", "-W", timeout_sec, ip]

            start_t = time.perf_counter()
            proc = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0

            if proc.returncode == 0:
                return IcmpHostResult(
                    ip=ip,
                    is_reachable=True,
                    rtt_ms=round(elapsed_ms, 2),
                    status="REACHABLE"
                )
            return IcmpHostResult(
                ip=ip,
                is_reachable=False,
                status="UNREACHABLE"
            )
        except Exception as e:
            return IcmpHostResult(
                ip=ip,
                is_reachable=False,
                status="ERROR",
                error=str(e)
            )

    def sweep(self, hosts: List[str], max_workers: int = 60) -> List[str]:
        """Executes concurrent ICMP reachability sweep returning active IP strings."""
        return icmp_sweep(hosts, max_workers=max_workers)

    def sweep_summary(self, hosts: List[str], max_workers: int = 60) -> IcmpSweepSummary:
        """Executes concurrent sweep returning typed IcmpSweepSummary."""
        start_t = time.perf_counter()
        reachable: List[str] = []
        unreachable: List[str] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            host_results = list(executor.map(lambda h: self.ping_host(h), hosts))

        for res in host_results:
            if res.is_reachable:
                reachable.append(res.ip)
            else:
                unreachable.append(res.ip)

        elapsed = time.perf_counter() - start_t
        return IcmpSweepSummary(
            total_hosts=len(hosts),
            reachable_hosts=reachable,
            unreachable_hosts=unreachable,
            elapsed_sec=round(elapsed, 3)
        )


__all__ = [
    "IcmpScanner",
    "IcmpScanPort",
    "IcmpHostResult",
    "IcmpSweepSummary",
    "ping_host_native",
    "icmp_sweep",
    "_MappingCompatibleModel",
]