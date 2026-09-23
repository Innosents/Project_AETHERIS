"""
Project AETHERIS - ARP Scanner Adapter
Discovers link-layer nodes through guarded Scapy ARP injection and OS neighbor
cache interrogation while exposing validated port models to callers.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from typing import Dict, List, Optional

from loguru import logger

from aetheris.core.ports.arp_scan_port import ArpDeviceRecord, ArpScanPort


class ArpScanner(ArpScanPort):
    """Concrete adapter for active ARP discovery and OS ARP-table parsing."""

    def scan(self, network_cidr: str) -> List[ArpDeviceRecord]:
        """Run guarded active discovery, then merge the native ARP table."""
        discovered: Dict[str, ArpDeviceRecord] = {}

        try:
            from scapy.all import srp
            from scapy.layers.l2 import ARP, Ether

            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr)
            answers, _ = srp(packet, timeout=1.5, verbose=False, inter=0.01)
            for _, response in answers:
                if response.psrc and response.hwsrc:
                    mac = response.hwsrc.upper().replace("-", ":")
                    discovered[response.psrc] = ArpDeviceRecord(
                        ip=response.psrc,
                        mac=mac,
                        source="scapy_raw_arp",
                    )
        except (PermissionError, OSError) as exc:
            logger.warning(
                "Raw ARP injection unavailable; using the OS ARP table: {}", exc
            )
        except Exception as exc:
            logger.warning(
                "Scapy ARP discovery unavailable; using the OS ARP table: {}", exc
            )

        try:
            output = subprocess.check_output(
                ["arp", "-a"],
                text=True,
                errors="ignore",
                timeout=2.0,
            )
            for record in self.parse_arp_table_output(output, network_cidr):
                discovered.setdefault(record.ip, record)
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("OS ARP table query unavailable: {}", exc)

        return list(discovered.values())

    @staticmethod
    def parse_arp_table_output(
        raw_output: str,
        target_cidr: Optional[str] = None,
    ) -> List[ArpDeviceRecord]:
        """Parse Windows ``arp -a`` output without invoking OS or network I/O."""
        try:
            target_network = (
                ipaddress.ip_network(target_cidr, strict=False)
                if target_cidr
                else None
            )
        except ValueError:
            target_network = None

        records: List[ArpDeviceRecord] = []
        seen_ips = set()
        pattern = re.compile(
            r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
            r"(?P<mac>[0-9a-fA-F:-]{17})\s+dynamic",
            re.IGNORECASE,
        )

        for line in raw_output.splitlines():
            match = pattern.search(line)
            if not match:
                continue

            ip = match.group("ip")
            mac = match.group("mac").replace("-", ":").upper()
            try:
                ip_object = ipaddress.ip_address(ip)
            except ValueError:
                continue

            if (
                ip in seen_ips
                or (target_network is not None and ip_object not in target_network)
                or ip_object.is_multicast
                or ip_object.is_reserved
                or mac == "FF:FF:FF:FF:FF:FF"
            ):
                continue

            seen_ips.add(ip)
            records.append(
                ArpDeviceRecord(ip=ip, mac=mac, source="os_arp_table")
            )

        return records


def arp_scan(network_cidr: str) -> List[ArpDeviceRecord]:
    """Backward-compatible functional alias backed by :class:`ArpScanner`."""
    return ArpScanner().scan(network_cidr)
