import asyncio
import time
import logging
from typing import Optional
from collections import deque
from scapy.all import AsyncSniffer, IP
from aetheris.core.ports.l2_ifg_inbound import IfgTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger('aetheris.adapters.microburst')

class MicroburstCaptureAdapter:
    def __init__(self, interface: str, event_bus: MemuraiEventBus, max_samples: int = 1000, loop: Optional[asyncio.AbstractEventLoop] = None):
        self.interface = interface
        self.bus = event_bus
        self.queue_name = 'aetheris:telemetry:ifg_intelligence'
        self.max_samples = max_samples
        self.buffers = {}  # Dict[str, deque]
        self.last_ts = {}  # Dict[str, int]
        try:
            self._loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self.sniffer: Optional[AsyncSniffer] = None

    def _ingest_frame(self, packet):
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        current_ns = time.perf_counter_ns()
        
        if src_ip not in self.buffers:
            self.buffers[src_ip] = deque(maxlen=self.max_samples)
            self.last_ts[src_ip] = current_ns
            return
            
        delta_t = current_ns - self.last_ts[src_ip]
        self.buffers[src_ip].append(delta_t)
        self.last_ts[src_ip] = current_ns
        
        # Emit intelligence when buffer reaches threshold
        if len(self.buffers[src_ip]) == self.max_samples:
            samples = list(self.buffers[src_ip])
            avg_ns = sum(samples) / self.max_samples
            var_ns = sum((x - avg_ns) ** 2 for x in samples) / self.max_samples
            hops = 1 if avg_ns < 150000 else 2
            
            self.buffers[src_ip].clear()
            try:
                telemetry = IfgTelemetryPort(
                    target_ip=src_ip,
                    avg_inter_frame_gap_ns=avg_ns,
                    jitter_variance_ns=var_ns,
                    sample_size=self.max_samples,
                    inferred_downstream_hops=hops
                )
                loop = self._loop
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(self.bus.push_telemetry(self.queue_name, telemetry.model_dump()), loop)
            except Exception as e:
                logger.error(f'Microburst payload validation failed: {e}')

    def start(self):
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        self.sniffer = AsyncSniffer(iface=self.interface, prn=self._ingest_frame, store=0)
        self.sniffer.start()
        logger.info(f'Microburst IFG Adapter armed on {self.interface}')

    def stop(self):
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.debug(f'Error stopping sniffer: {e}')
            self.sniffer = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

