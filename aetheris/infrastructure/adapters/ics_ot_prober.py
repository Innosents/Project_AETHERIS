"""
Project AETHERIS - Industrial OT & BACnet/IP Infrastructure Adapter
Executes asynchronous BACnet/IP inquiries over UDP port 47808, measures high-resolution
kernel turnaround timing, and dispatches validated telemetry directly to Memurai.
"""

import asyncio
import socket
import time
import struct
import logging
from typing import Optional, Tuple, Dict, Any
from aetheris.core.ports.l7_ics_inbound import IndustrialTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.ics_ot")
BACNET_INQUIRY = b"\x81\x0a\x00\x0e\x01\x20\xff\xff\x00\xff\x10\x0c\x0c\x02\x00\x00\x00\x19\x4d"


class IcsOtAdapter:
    """
    Decoupled Industrial OT and BACnet/IP infrastructure adapter.
    Dispatches non-blocking threadpool UDP queries to target endpoints and publishes
    validated telemetry to 'aetheris:telemetry:ics_intelligence'.
    """

    def __init__(self, event_bus: MemuraiEventBus, timeout: float = 0.5) -> None:
        self.bus = event_bus
        self.timeout = min(0.5, timeout)
        self.consume_queue = "aetheris:telemetry:l3_active"
        self.publish_queue = "aetheris:telemetry:ics_intelligence"

    def _parse_bacnet(self, data: bytes) -> Tuple[bool, Optional[int]]:
        """Parses BVLC header and extracts 22-bit BACnet Object Instance ID."""
        if not data or len(data) < 4 or data[0] != 0x81:
            return False, None
        for i in range(len(data) - 4):
            if data[i] == 0xC4:
                dev_id = struct.unpack(">I", data[i + 1 : i + 5])[0] & 0x3FFFFF
                return True, dev_id
        return True, None

    def _execute_bacnet_probe(self, ip: str) -> Optional[Dict[str, Any]]:
        """Synchronous UDP probe executed within worker thread pool."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        try:
            t_start = time.perf_counter_ns()
            s.sendto(BACNET_INQUIRY, (ip, 47808))
            data, _ = s.recvfrom(2048)
            t_end = time.perf_counter_ns()

            if not data:
                return None

            is_valid, dev_id = self._parse_bacnet(data)
            if not is_valid:
                return None

            turnaround_ns = max(1, t_end - t_start)
            return {
                "kernel_turnaround_us": turnaround_ns / 1000.0,
                "latency_ms": turnaround_ns / 1e6,
                "device_instance": dev_id,
                "model": (
                    f"BACnet Controller (Instance {dev_id})"
                    if dev_id
                    else "BACnet Building Controller"
                ),
            }
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass

    async def process_target(self, target_ip: str) -> None:
        """Asynchronously dispatches BACnet probe and streams validated port to Memurai."""
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self._execute_bacnet_probe, target_ip)

        if result:
            try:
                telemetry = IndustrialTelemetryPort(
                    target_ip=target_ip,
                    port=47808,
                    protocol="BACnet/IP",
                    vendor="BACnet Building Automation",
                    model=result["model"],
                    device_instance=result["device_instance"],
                    archetype="INDUSTRIAL_OT",
                    device_type="bacnet_controller",
                    kernel_turnaround_us=result["kernel_turnaround_us"],
                    latency_ms=result["latency_ms"],
                )
                await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
            except Exception as e:
                logger.error(f"ICS OT payload validation failed: {e}")

