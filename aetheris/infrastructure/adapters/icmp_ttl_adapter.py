"""
Project AETHERIS - ICMP TTL & Topological Depth Infrastructure Adapter
Executes non-intrusive ICMP echo interrogations and derives topological depth
from OS TTL decrement physics, dispatching validated telemetry to Memurai.
"""

import asyncio
import os
import socket
import struct
import time
import logging
from typing import List, Dict, Optional, Any
from aetheris.core.ports.l3_ttl_inbound import TtlTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.icmp_ttl")


def _icmp_checksum(data: bytes) -> int:
    """Computes RFC 1071 Internet Checksum for ICMP packets."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_icmp_echo(identifier: int, seq: int) -> bytes:
    """Constructs an ICMP Echo Request (Type 8, Code 0) with RFC 1071 checksum."""
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, seq)
    payload = b"AETHERIS" * 4
    chksum = _icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, chksum, identifier, seq)
    return header + payload


class IcmpTtlAdapter:
    """
    Decoupled asynchronous ICMP TTL topology adapter.
    Dispatches concurrent probes across target IPs using SOCK_RAW with fallback,
    correlates responses, and routes validated hop counts to 'aetheris:telemetry:l3_ttl_intel'.
    """

    def __init__(self, event_bus: MemuraiEventBus, timeout: float = 0.5) -> None:
        self.bus = event_bus
        self.timeout = timeout
        self.consume_queue = "aetheris:telemetry:l3_active"
        self.publish_queue = "aetheris:telemetry:l3_ttl_intel"
        self._identifier = os.getpid() & 0xFFFF

    def _determine_baseline(self, returning_ttl: int) -> int:
        """Infers original OS-level initial TTL baseline."""
        for baseline in [64, 128, 255]:
            if returning_ttl <= baseline:
                return baseline
        return 255

    def _execute_raw_sweep(self, target_ips: List[str]) -> Dict[str, int]:
        """Dispatches ICMP Echo Requests and ingests Echo Replies to record returning TTL."""
        results: Dict[str, int] = {}
        seq_to_ip: Dict[int, str] = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
        except (PermissionError, OSError):
            logger.warning("Raw socket permission denied. ICMP TTL sweep bypassed.")
            return self._fallback_sweep(target_ips)

        try:
            for seq, ip in enumerate(target_ips):
                seq_to_ip[seq] = ip
                packet = _build_icmp_echo(self._identifier, seq)
                try:
                    sock.sendto(packet, (ip, 0))
                except Exception:
                    pass

            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                try:
                    remaining = max(0.001, deadline - time.monotonic())
                    sock.settimeout(remaining)
                    data, _ = sock.recvfrom(1024)
                    if len(data) >= 28 and data[20] == 0:
                        icmp_id = struct.unpack("!H", data[24:26])[0]
                        icmp_seq = struct.unpack("!H", data[26:28])[0]
                        if icmp_id == self._identifier and icmp_seq in seq_to_ip:
                            results[seq_to_ip[icmp_seq]] = data[8]
                except socket.timeout:
                    break
                except Exception:
                    continue
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return results

    def _fallback_sweep(self, target_ips: List[str]) -> Dict[str, int]:
        """Fallback prober using Scapy for non-raw socket execution environments."""
        results: Dict[str, int] = {}
        try:
            from scapy.all import IP, ICMP, sr1
            for target_ip in target_ips:
                try:
                    pkt = IP(dst=target_ip) / ICMP()
                    ans = sr1(pkt, timeout=self.timeout, verbose=0)
                    if ans and IP in ans:
                        results[target_ip] = ans[IP].ttl
                except Exception:
                    pass
        except ImportError:
            pass
        return results

    async def process_targets(self, target_ips: List[str]) -> Dict[str, int]:
        """Asynchronously processes target IPs, derives hop count, and publishes telemetry."""
        loop = asyncio.get_running_loop()
        raw_results = await loop.run_in_executor(None, self._execute_raw_sweep, target_ips)
        derived_hops: Dict[str, int] = {}

        for ip, returning_ttl in raw_results.items():
            baseline = self._determine_baseline(returning_ttl)
            hop_count = max(0, baseline - returning_ttl)
            derived_hops[ip] = hop_count
            try:
                telemetry = TtlTelemetryPort(
                    target_ip=ip,
                    baseline_ttl=baseline,
                    hop_count=hop_count,
                )
                await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
            except Exception as e:
                logger.error(f"TTL payload validation failed: {e}")

        return derived_hops

