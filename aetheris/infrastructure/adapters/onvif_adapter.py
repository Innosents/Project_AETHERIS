"""
Project AETHERIS - ONVIF Camera Infrastructure Adapter
Consumes target IP addresses from 'aetheris:telemetry:l3_active', executes
non-blocking HTTP/SOAP GetDeviceInformation inquiries on port 80/8000,
validates telemetry through OnvifTelemetryPort, and publishes to
'aetheris:telemetry:camera_intelligence'.
"""

import asyncio
import logging
from typing import Optional

from aetheris.core.ports.l7_onvif_inbound import OnvifTelemetryPort
from aetheris.core.parsers.onvif_parser import probe_onvif_camera
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.onvif")


class OnvifAdapter:
    """
    Decoupled ONVIF surveillance camera infrastructure adapter.
    Executes non-blocking HTTP/SOAP device service queries, validates
    camera hardware telemetry, and publishes events to the Memurai bus.
    """

    def __init__(self, event_bus: Optional[MemuraiEventBus] = None, timeout: float = 0.5):
        self.bus = event_bus
        self.timeout = min(0.5, timeout)
        self.consume_queue = "aetheris:telemetry:l3_active"
        self.publish_queue = "aetheris:telemetry:camera_intelligence"

    async def process_target(self, target_ip: str, port: int = 80) -> None:
        """
        Interrogates target ONVIF camera device service non-blockingly, validates
        telemetry invariants, and streams to Memurai event bus.
        """
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, probe_onvif_camera, target_ip, port, self.timeout)
        if data and data.get("is_onvif"):
            try:
                telemetry = OnvifTelemetryPort(
                    target_ip=target_ip,
                    port=port,
                    protocol=data.get("protocol", f"ONVIF Device Service (Port {port})"),
                    vendor=data.get("vendor", "Generic ONVIF"),
                    model=data.get("model", "IP Surveillance Camera"),
                    firmware=data.get("firmware", ""),
                    serial_number=data.get("serial_number", ""),
                    hardware_id=data.get("hardware_id", ""),
                    kernel_turnaround_us=data.get("kernel_turnaround_us", 0.0),
                    latency_ms=data.get("latency_ms", 0.0),
                )
                if self.bus:
                    await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
            except Exception as e:
                logger.error(f"ONVIF telemetry validation failed for {target_ip}: {e}")

