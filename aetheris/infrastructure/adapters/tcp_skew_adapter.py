"""
Project AETHERIS - TCP Clock Skew & Hidden NAT Detection Adapter
Passively ingests RFC 1323/7323 TCP Timestamps, clusters clock frequencies,
and routes validated telemetry directly to Memurai.
"""

import asyncio
import time
import logging
from collections import defaultdict, deque
from typing import Optional, List, Dict, Any, Deque, Tuple
from scapy.all import AsyncSniffer, IP, TCP
from aetheris.core.ports.l3_tcp_skew_inbound import TcpSkewTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.tcp_skew")


class TcpSkewCaptureAdapter:
    """
    Decoupled passive L3 TCP clock skew listener streaming validated telemetry
    to 'aetheris:telemetry:tcp_skew_intel'.
    """

    def __init__(
        self,
        interface: str,
        event_bus: MemuraiEventBus,
        capture_window_samples: int = 50,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.interface = interface
        self.bus = event_bus
        self.queue_name = "aetheris:telemetry:tcp_skew_intel"
        self.capture_window_samples = capture_window_samples
        self.flow_matrix: Dict[str, Dict[int, Deque[Tuple[float, int]]]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=self.capture_window_samples))
        )
        try:
            self._loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self.sniffer: Optional[AsyncSniffer] = None

    def _process_packet(self, packet: Any) -> None:
        """Processes TCP packets to extract TSval options per ephemeral flow."""
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        src_ip = packet[IP].src
        sport = packet[TCP].sport
        options = packet[TCP].options

        ts_opt = next((opt[1] for opt in options if isinstance(opt, tuple) and opt[0] == "Timestamp"), None)

        if ts_opt and isinstance(ts_opt, tuple) and len(ts_opt) == 2:
            tsval = ts_opt[0]
            arrival_time = time.perf_counter()
            self.flow_matrix[src_ip][sport].append((arrival_time, tsval))

            # Trigger entropy calculation and flush if window saturates
            if len(self.flow_matrix[src_ip][sport]) == self.capture_window_samples:
                self._evaluate_and_dispatch(src_ip)

    def _evaluate_and_dispatch(self, src_ip: str) -> None:
        """Calculates clock entropy and dispatches validated telemetry to event bus."""
        distinct_clocks: List[int] = []
        clock_frequencies: List[float] = []

        for sport, observations in list(self.flow_matrix[src_ip].items()):
            if len(observations) < 5:
                continue

            valid_intervals: List[Tuple[float, int]] = []
            for i in range(1, len(observations)):
                dt = observations[i][0] - observations[i - 1][0]
                dts = observations[i][1] - observations[i - 1][1]
                if dt > 0 and dts >= 0:
                    valid_intervals.append((dt, dts))

            if len(valid_intervals) < 4:
                continue

            # Sliding window variance algorithm: discard top 5% buffer bloat anomalies
            valid_intervals.sort(key=lambda x: x[0])
            cutoff_idx = max(1, int(len(valid_intervals) * 0.95))
            filtered = valid_intervals[:cutoff_idx]
            total_dt = sum(x[0] for x in filtered)
            total_dts = sum(x[1] for x in filtered)

            if total_dt > 0:
                distinct_clocks.append(observations[0][1])
                clock_frequencies.append(round(total_dts / total_dt, 2))

            # Clear evaluated flow to prevent memory bleed
            del self.flow_matrix[src_ip][sport]

        if not distinct_clocks:
            return

        max_ts_offset = max(distinct_clocks) - min(distinct_clocks)
        nat_detected = max_ts_offset > 1000000 or len(set([round(f, -1) for f in clock_frequencies])) > 1

        try:
            telemetry = TcpSkewTelemetryPort(
                target_ip=src_ip,
                active_ephemeral_flows=len(distinct_clocks),
                clock_spread_ticks=max_ts_offset,
                detected_kernel_frequencies_hz=clock_frequencies,
                hidden_nat_detected=nat_detected,
            )
            loop = self._loop
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.bus.push_telemetry(self.queue_name, telemetry.model_dump()),
                    loop,
                )
        except Exception as e:
            logger.error(f"TCP Skew validation failed: {e}")

    def start(self) -> None:
        """Starts asynchronous packet capture on interface."""
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter="tcp",
            prn=self._process_packet,
            store=0,
        )
        self.sniffer.start()
        logger.info(f"TCP Clock Skew Adapter armed on {self.interface}")

    def stop(self) -> None:
        """Terminates active packet sniffer."""
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.debug(f"Error stopping sniffer: {e}")
            self.sniffer = None

    def __enter__(self) -> "TcpSkewCaptureAdapter":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

