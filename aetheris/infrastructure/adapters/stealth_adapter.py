"""
Project AETHERIS - L3 Stealth Probing Infrastructure Adapter
Executes concurrent non-blocking UDP interrogations (NetBIOS, WS-Discovery, LLMNR)
via asyncio.gather, validates telemetry invariants through StealthTelemetryPort,
and streams events to the Memurai bus ('aetheris:telemetry:stealth_identity').
"""

import asyncio
import logging
import socket
import time
from typing import Dict, Any, Optional, Tuple

from aetheris.core.ports.l3_stealth_inbound import StealthTelemetryPort
from aetheris.core.parsers.stealth_parser import (
    NETBIOS_NBSTAT_QUERY,
    build_wsd_probe,
    build_llmnr_query,
    parse_netbios_response,
    parse_wsd_response,
    parse_llmnr_response,
)
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.stealth")


class StealthAdapter:
    """
    Decoupled multi-variance stealth host interrogation infrastructure adapter.
    Executes non-blocking UDP sweeps across ports 137, 3702, and 5355 without
    blocking the asyncio event loop, and normalizes telemetry into StealthTelemetryPort.
    """

    def __init__(self, event_bus: Optional[MemuraiEventBus] = None, timeout: float = 0.5):
        self.bus = event_bus
        self.timeout = timeout
        self.consume_queue = "aetheris:telemetry:l3_active"
        self.publish_queue = "aetheris:telemetry:stealth_identity"

    def _udp_transceive(self, ip: str, port: int, payload: bytes, timeout: float) -> Tuple[bytes, float]:
        """Synchronous UDP transceive measuring kernel turnaround latency in nanoseconds."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                t_start = time.perf_counter_ns()
                s.sendto(payload, (ip, port))
                data, _ = s.recvfrom(4096)
                t_end = time.perf_counter_ns()
                turnaround_us = max(1, t_end - t_start) / 1000.0
                return data, turnaround_us
        except Exception:
            return b"", 0.0

    async def probe_endpoint(self, ip: str) -> Optional[StealthTelemetryPort]:
        """
        Executes concurrent NetBIOS, WS-Discovery, and LLMNR probes non-blockingly
        using asyncio.gather and loop.run_in_executor.
        """
        loop = asyncio.get_running_loop()
        wsd_payload, _ = build_wsd_probe()
        llmnr_payload = build_llmnr_query(ip)

        nb_task = loop.run_in_executor(None, self._udp_transceive, ip, 137, NETBIOS_NBSTAT_QUERY, min(self.timeout, 0.35))
        wsd_task = loop.run_in_executor(None, self._udp_transceive, ip, 3702, wsd_payload, min(self.timeout, 0.4))
        llmnr_task = loop.run_in_executor(None, self._udp_transceive, ip, 5355, llmnr_payload, min(self.timeout, 0.35))

        (nb_data, nb_tk), (wsd_data, wsd_tk), (llmnr_data, llmnr_tk) = await asyncio.gather(nb_task, wsd_task, llmnr_task)

        sub_probes: Dict[str, Any] = {}
        nb_res = parse_netbios_response(nb_data)
        if nb_res:
            nb_res["kernel_turnaround_us"] = nb_tk
            sub_probes["netbios"] = nb_res

        wsd_res = parse_wsd_response(wsd_data)
        if wsd_res:
            wsd_res["kernel_turnaround_us"] = wsd_tk
            sub_probes["ws_discovery"] = wsd_res

        llmnr_res = parse_llmnr_response(llmnr_data)
        if llmnr_res:
            llmnr_res["kernel_turnaround_us"] = llmnr_tk
            sub_probes["llmnr"] = llmnr_res

        if not sub_probes:
            return None

        hostname = (
            sub_probes.get("netbios", {}).get("hostname")
            or sub_probes.get("ws_discovery", {}).get("hostname")
            or sub_probes.get("llmnr", {}).get("hostname")
            or ""
        )
        mac_addr = sub_probes.get("netbios", {}).get("mac", "")
        vendor = (
            sub_probes.get("ws_discovery", {}).get("vendor")
            or sub_probes.get("netbios", {}).get("vendor")
            or "generic"
        )
        dev_type = (
            sub_probes.get("ws_discovery", {}).get("type")
            or sub_probes.get("netbios", {}).get("type")
            or "workstation"
        )
        model = (
            sub_probes.get("ws_discovery", {}).get("model")
            or sub_probes.get("netbios", {}).get("model")
            or "Network Endpoint"
        )

        tks = [p["kernel_turnaround_us"] for p in sub_probes.values() if p.get("kernel_turnaround_us", 0) > 0]
        min_tk = min(tks) if tks else 150.0

        return StealthTelemetryPort(
            ip=ip,
            hostname=hostname,
            mac=mac_addr,
            vendor=vendor,
            type=dev_type,
            model=model,
            kernel_turnaround_us=min_tk,
            latency_ms=min_tk / 1000.0,
            probes=sub_probes,
        )

    async def process_target(self, target_ip: str) -> Optional[StealthTelemetryPort]:
        """Probes target endpoint and publishes validated telemetry to Memurai bus."""
        telemetry = await self.probe_endpoint(target_ip)
        if telemetry and self.bus:
            await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
        return telemetry

