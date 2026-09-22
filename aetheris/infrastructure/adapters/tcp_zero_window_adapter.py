"""
Project AETHERIS - L3 TCP Zero-Window Infrastructure Adapter
Sniffs promiscuous or SPAN mirror traffic to monitor TCP zero-window events,
measures flow collapse persistence, and streams alerts to Memurai
('aetheris:telemetry:os_buffer_collapse').
"""

import asyncio
import logging
from collections import defaultdict
from typing import Any, Dict, Optional

from scapy.all import AsyncSniffer

from aetheris.core.ports.l3_window_inbound import TcpZeroWindowTelemetryPort
from aetheris.core.parsers.tcp_window_parser import (
    inspect_tcp_zero_window,
    evaluate_exhaustion_matrix,
)
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.tcp_window")


class TcpZeroWindowAdapter:
    """
    Decoupled TCP Zero-Window Receive Buffer Exhaustion Adapter.
    Passively monitors TCP flows for window collapse, filters transient stalls,
    and publishes sustained buffer exhaustion events to the Memurai event bus.
    """

    def __init__(
        self,
        event_bus: Optional[MemuraiEventBus] = None,
        interface: str = "Ethernet 2",
        timeout: float = 45.0,
    ):
        self.bus = event_bus
        self.interface = interface
        self.timeout = timeout
        self.publish_queue = "aetheris:telemetry:os_buffer_collapse"
        self.collapse_matrix: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "timestamps": []})
        self.sniffer: Optional[AsyncSniffer] = None

    def _on_packet(self, packet: Any) -> None:
        """Processes an incoming frame for zero-window collapse conditions."""
        res = inspect_tcp_zero_window(packet)
        if res:
            flow_key, ts = res
            self.collapse_matrix[flow_key]["count"] += 1
            self.collapse_matrix[flow_key]["timestamps"].append(ts)

    # Legacy compatibility alias
    _frame_callback = _on_packet

    async def monitor_target(
        self, target_ip: str, duration: Optional[float] = None
    ) -> TcpZeroWindowTelemetryPort:
        """
        Runs passive BPF sniffing against the target IP or entire segment for the specified duration.
        Evaluates exhaustion matrix and pushes sustained alerts to the Memurai bus.
        """
        dur = duration if duration is not None else self.timeout
        bpf = f"tcp and src host {target_ip}" if target_ip != "0.0.0.0" else "tcp"
        self.sniffer = AsyncSniffer(iface=self.interface, filter=bpf, prn=self._on_packet, store=0)
        try:
            self.sniffer.start()
            await asyncio.sleep(dur)
        finally:
            try:
                self.sniffer.stop()
            except Exception:
                pass

        status, sustained = evaluate_exhaustion_matrix(self.collapse_matrix)
        telemetry = TcpZeroWindowTelemetryPort(
            target_ip=target_ip,
            status=status,
            capture_duration_sec=dur,
            exhaustion_matrix=sustained,
        )
        if sustained and self.bus:
            await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
        return telemetry

    def reset(self) -> None:
        """Purges in-memory flow collapse structures."""
        self.collapse_matrix.clear()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.reset()
        return False

