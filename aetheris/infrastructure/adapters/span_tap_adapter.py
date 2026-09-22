"""
Project AETHERIS - L2 SPAN/TAP Promiscuous Ingestion Adapter
Encapsulates Scapy AsyncSniffer hardware binding, ERSPAN/GRE decapsulation,
and non-blocking delegate dispatch for L2/L3 spatial analysis.
"""

import asyncio
import logging
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional

from scapy.all import AsyncSniffer, UDP
from scapy.contrib.cdp import CDPv2_HDR
from scapy.contrib.lldp import LLDPDU
from scapy.layers.l2 import STP

from aetheris.core.ports.l2_span_inbound import SpanCaptureTelemetryPort
from aetheris.core.parsers.span_parser import (
    decapsulate_erspan,
    MAC_STP,
    MAC_LLDP,
    MAC_CDP,
    MULTICAST_UDP_PORTS,
)
from aetheris.core.parsers.sanitization import sanitize_prober_payload

logger = logging.getLogger("aetheris.adapters.span_tap")


class SpanTapAdapter:
    """
    Decoupled Promiscuous Network TAP Infrastructure Adapter.
    Binds to local or virtual interfaces with promisc fallback, demultiplexes
    raw frames to protocol subscribers, and reports verified telemetry metrics.
    """

    def __init__(self, interface: str = "eth0", telemetry_context: Optional[Dict[str, Any]] = None):
        self.telemetry_context = telemetry_context or {}
        self.interface = self.telemetry_context.get("span_interface", interface)
        self._subscribers: Dict[str, List[Callable[[Any], None]]] = defaultdict(list)
        self.sniffer: Optional[AsyncSniffer] = None
        self._is_running: bool = False
        self.stats: Dict[str, int] = {
            "total_frames": 0,
            "chassis_frames": 0,
            "stp_frames": 0,
            "multicast_frames": 0,
            "unhandled_frames": 0,
        }

    def register_delegate(self, channel: str, callback: Callable[[Any], None]) -> None:
        """Registers a protocol delegate callback for a specific channel."""
        if callback not in self._subscribers[channel]:
            self._subscribers[channel].append(callback)

    def unregister_delegate(self, channel: str, callback: Callable[[Any], None]) -> bool:
        """Removes a registered delegate from the specified channel."""
        if callback in self._subscribers.get(channel, []):
            self._subscribers[channel].remove(callback)
            return True
        return False

    def _dispatch(self, channel: str, packet: Any) -> None:
        """Dispatches a frame to all channel subscribers with zero lock overhead."""
        for callback in self._subscribers.get(channel, []):
            try:
                callback(packet)
            except Exception as e:
                logger.debug("Delegate error on channel %s: %s", channel, e)

    def _packet_callback(self, packet: Any) -> None:
        """Unified packet ingestion loop and protocol demultiplexing."""
        self.stats["total_frames"] += 1
        if self._subscribers.get("raw"):
            self._dispatch("raw", packet)

        frame = decapsulate_erspan(packet) or packet
        dispatched = False

        if frame.haslayer(STP) or getattr(frame, "dst", "") == MAC_STP:
            self.stats["stp_frames"] += 1
            self._dispatch("stp_intelligence", frame)
            dispatched = True

        if frame.haslayer(CDPv2_HDR) or frame.haslayer(LLDPDU) or getattr(frame, "dst", "") in (MAC_CDP, MAC_LLDP):
            self.stats["chassis_frames"] += 1
            self._dispatch("chassis_intelligence", frame)
            dispatched = True

        if frame.haslayer(UDP):
            udp = frame[UDP]
            if udp.sport in MULTICAST_UDP_PORTS or udp.dport in MULTICAST_UDP_PORTS:
                self.stats["multicast_frames"] += 1
                self._dispatch("multicast_identity", frame)
                dispatched = True

        if not dispatched:
            self.stats["unhandled_frames"] += 1

    # Drop-in compatibility alias
    _unified_packet_loop = _packet_callback

    def start(self) -> None:
        """Arms the promiscuous AsyncSniffer tap."""
        if self._is_running:
            return
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface, promisc=True, store=0, prn=self._packet_callback
            )
            self.sniffer.start()
            self._is_running = True
        except Exception as e:
            logger.warning("Failed to bind promisc on %s: %s. Falling back.", self.interface, e)
            self.sniffer = AsyncSniffer(promisc=False, store=0, prn=self._packet_callback)
            self.sniffer.start()
            self._is_running = True

    def stop(self) -> Dict[str, Any]:
        """Disarms the sniffer and returns sanitized telemetry statistics."""
        if self.sniffer and self._is_running:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self._is_running = False
        payload = {
            "interface": self.interface,
            "status": "STOPPED",
            "stats": dict(self.stats),
        }
        return sanitize_prober_payload(payload)

    def get_telemetry(self) -> SpanCaptureTelemetryPort:
        """Returns validated Pydantic telemetry port snapshot."""
        return SpanCaptureTelemetryPort(
            interface=self.interface,
            status="RUNNING" if self._is_running else "STOPPED",
            **self.stats
        )

    async def run(self, duration_sec: float = 65.0) -> Dict[str, Any]:
        """Runs the tap asynchronously for a bounded duration."""
        self.start()
        try:
            await asyncio.sleep(duration_sec)
        finally:
            return self.stop()

    async def __aenter__(self):
        self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


# Compatibility alias
SpanCaptureEngine = SpanTapAdapter

