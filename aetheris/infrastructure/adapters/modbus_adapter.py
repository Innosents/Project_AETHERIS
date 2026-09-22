"""
Project AETHERIS - Modbus TCP Industrial Automation Infrastructure Adapter
Consumes target IP addresses from 'aetheris:telemetry:l3_active', executes
non-blocking MEI Read Device Identification queries over TCP port 502, and
publishes validated IndustrialTelemetryPort records to 'aetheris:telemetry:ics_intelligence'.
"""

import asyncio
import logging
import socket
import time
from typing import Optional, Dict, Any

from aetheris.core.ports.l7_ics_inbound import IndustrialTelemetryPort
from aetheris.core.parsers.industrial_parser import (
    parse_modbus_mei_response,
    MODBUS_READ_DEVICE_ID,
    parse_bacnet_response,
    BACNET_READ_PROPERTY_INQUIRY,
)
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.modbus")


class ModbusAdapter:
    """
    Decoupled Industrial OT (Modbus TCP & BACnet/IP) infrastructure adapter.
    Dispatches non-blocking threadpool queries, measures kernel turnaround timing,
    and publishes validated IndustrialTelemetryPort telemetry to Memurai.
    """

    def __init__(self, event_bus: Optional[MemuraiEventBus] = None, timeout: float = 0.5):
        self.bus = event_bus
        self.timeout = min(0.5, timeout)
        self.consume_queue = "aetheris:telemetry:l3_active"
        self.publish_queue = "aetheris:telemetry:ics_intelligence"

    def _probe_socket(self, ip: str, port: int) -> Dict[str, Any]:
        """Synchronous TCP probe executed within worker thread pool."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((ip, port))
            t_start = time.perf_counter_ns()
            s.sendall(MODBUS_READ_DEVICE_ID)
            resp = s.recv(1024)
            t_end = time.perf_counter_ns()

            if not resp or len(resp) < 8:
                return {}

            turnaround_ns = max(1, t_end - t_start)
            parsed = parse_modbus_mei_response(resp)
            return {
                "vendor": parsed["vendor"],
                "model": parsed["model"],
                "firmware": parsed["firmware"],
                "kernel_turnaround_us": turnaround_ns / 1000.0,
                "latency_ms": turnaround_ns / 1e6,
            }
        except Exception:
            return {}
        finally:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass

    def _probe_bacnet_socket(self, ip: str, port: int = 47808) -> Dict[str, Any]:
        """Synchronous UDP BACnet/IP probe executed within worker thread pool."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        try:
            t_start = time.perf_counter_ns()
            s.sendto(BACNET_READ_PROPERTY_INQUIRY, (ip, port))
            data, _ = s.recvfrom(2048)
            t_end = time.perf_counter_ns()

            if not data:
                return {}

            parsed = parse_bacnet_response(data)
            if not parsed.get("is_valid"):
                return {}

            turnaround_ns = max(1, t_end - t_start)
            return {
                "vendor": parsed["vendor"],
                "model": parsed["model"],
                "device_instance": parsed.get("device_instance"),
                "kernel_turnaround_us": turnaround_ns / 1000.0,
                "latency_ms": turnaround_ns / 1e6,
            }
        except Exception:
            return {}
        finally:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass

    async def process_target(self, target_ip: str, port: int = 502) -> Optional[IndustrialTelemetryPort]:
        """
        Asynchronously executes threadpool Modbus probe, constructs IndustrialTelemetryPort,
        and publishes validated telemetry to the Memurai bus.
        """
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, self._probe_socket, target_ip, port)
        if data:
            try:
                telemetry = IndustrialTelemetryPort(
                    target_ip=target_ip,
                    port=port,
                    protocol=f"Modbus TCP (Port {port})",
                    vendor=data["vendor"],
                    model=data["model"],
                    archetype="INDUSTRIAL_OT",
                    device_type="modbus_plc",
                    kernel_turnaround_us=data["kernel_turnaround_us"],
                    latency_ms=data["latency_ms"],
                )
                if self.bus:
                    await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
                return telemetry
            except Exception as e:
                logger.error(f"Modbus validation failed for {target_ip}: {e}")
        return None

    async def process_bacnet_target(self, target_ip: str, port: int = 47808) -> Optional[IndustrialTelemetryPort]:
        """
        Asynchronously executes threadpool BACnet/IP probe, constructs IndustrialTelemetryPort,
        and publishes validated telemetry to the Memurai bus.
        """
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, self._probe_bacnet_socket, target_ip, port)
        if data:
            try:
                telemetry = IndustrialTelemetryPort(
                    target_ip=target_ip,
                    port=port,
                    protocol=f"BACnet/IP (UDP {port})",
                    vendor=data.get("vendor", "BACnet Building Automation"),
                    model=data.get("model", "BACnet Building Controller"),
                    device_instance=data.get("device_instance"),
                    archetype="INDUSTRIAL_OT",
                    device_type="bacnet_controller",
                    kernel_turnaround_us=data["kernel_turnaround_us"],
                    latency_ms=data["latency_ms"],
                )
                if self.bus:
                    await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
                return telemetry
            except Exception as e:
                logger.error(f"BACnet validation failed for {target_ip}: {e}")
        return None


# Industrial adapter alias
IndustrialAdapter = ModbusAdapter

__all__ = ["ModbusAdapter", "IndustrialAdapter", "MODBUS_READ_DEVICE_ID", "BACNET_READ_PROPERTY_INQUIRY"]


