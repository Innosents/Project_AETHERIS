"""
Project AETHERIS - Mercury Security MSP Infrastructure Adapter
Consumes target IP addresses from 'aetheris:telemetry:l3_active', manages
TCP stream communication on port 3001, emits ACK payloads, and dispatches
validated telemetry to 'aetheris:telemetry:physical_security'.
"""

import asyncio
import logging
import socket
import time
from typing import Optional

from aetheris.core.ports.l7_mercury_inbound import MercuryMspTelemetryPort, MercuryPanelTelemetryPort
from aetheris.core.parsers.mercury_parser import (
    parse_msp_frame,
    ACK_PAYLOAD,
    parse_mercury_response,
    MERCURY_STATUS_INQUIRY,
)
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.mercury")


class MercuryMspAdapter:
    """
    Decoupled Mercury MSP infrastructure adapter.
    Establishes non-blocking stream connections to target access controllers,
    parses downstream RS-485 sub-node topology, and publishes validated telemetry.
    """

    def __init__(self, event_bus: Optional[MemuraiEventBus] = None, timeout: float = 0.5):
        self.bus = event_bus
        self.timeout = min(0.5, timeout)
        self.consume_queue = "aetheris:telemetry:l3_active"
        self.publish_queue = "aetheris:telemetry:physical_security"

    async def process_target(self, target_ip: str, port: int = 3001) -> None:
        """
        Connects to a Mercury controller on port 3001, ingests framed MSP buffer,
        emits positive ACK, validates telemetry, and streams to Memurai bus.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port), timeout=self.timeout
            )
        except (OSError, asyncio.TimeoutError):
            return

        buffer = bytearray()
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                buffer.extend(chunk)
                if b"\x03" in buffer:
                    break

            if not buffer:
                return

            topology = parse_msp_frame(bytes(buffer))
            writer.write(ACK_PAYLOAD)
            await writer.drain()

            telemetry = MercuryMspTelemetryPort(
                target_ip=target_ip,
                target_port=port,
                readers=topology["readers"],
                rex=topology["rex"],
                strikes=topology["strikes"],
                dps=topology["dps"],
            )

            if self.bus:
                await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
        except Exception as e:
            logger.error(f"Mercury MSP probe failure on {target_ip}: {e}")
        finally:
            try:
                sock = writer.get_extra_info("socket")
                if sock:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def process_panel_target(self, target_ip: str, port: int = 3001) -> None:
        """Handles binary status inquiry against Mercury controller alongside MSP streaming."""
        panel_adapter = MercuryPanelAdapter(event_bus=self.bus, timeout=self.timeout)
        await panel_adapter.process_target(target_ip, port=port)


class MercuryPanelAdapter:
    """
    Decoupled Mercury Security panel binary inquiry infrastructure adapter.
    Transmits status inquiry frames to port 3001, calculates microsecond kernel turnaround,
    extracts model/firmware metadata, and dispatches validated telemetry to 'aetheris:telemetry:physical_security'.
    """

    def __init__(self, event_bus: Optional[MemuraiEventBus] = None, timeout: float = 0.5):
        self.bus = event_bus
        self.timeout = min(0.5, timeout)
        self.consume_queue = "aetheris:telemetry:l3_active"
        self.publish_queue = "aetheris:telemetry:physical_security"

    def _probe_socket(self, ip: str, port: int) -> dict:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((ip, port))
            t_start = time.perf_counter_ns()
            s.sendall(MERCURY_STATUS_INQUIRY)
            resp = s.recv(1024)
            t_end = time.perf_counter_ns()
            if not resp:
                return {}
            turnaround_ns = max(1, t_end - t_start)
            parsed = parse_mercury_response(resp)
            return {
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

    async def process_target(self, target_ip: str, port: int = 3001) -> None:
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, self._probe_socket, target_ip, port)
        if data:
            try:
                telemetry = MercuryPanelTelemetryPort(
                    target_ip=target_ip,
                    port=port,
                    model=data["model"],
                    firmware=data["firmware"],
                    kernel_turnaround_us=data["kernel_turnaround_us"],
                    latency_ms=data["latency_ms"],
                )
                if self.bus:
                    await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
            except Exception as e:
                logger.error(f"Mercury Panel validation failed for {target_ip}: {e}")

