import asyncio
import logging
from typing import Optional
from scapy.all import AsyncSniffer, Ether, UDP
from aetheris.core.ports.l7_dpi_inbound import DpiTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus
from aetheris.core.parsers.dpi_parser import (
    UbntDiscoveryDecoder,
    MikrotikMndpDecoder,
    BacnetIpDecoder,
    StpBpduDecoder,
)

logger = logging.getLogger('aetheris.adapters.passive_dpi')

class PassiveDpiAdapter:
    def __init__(self, interface: str, event_bus: MemuraiEventBus, loop: Optional[asyncio.AbstractEventLoop] = None):
        self.interface = interface
        self.bus = event_bus
        self.queue_name = 'aetheris:telemetry:dpi_intelligence'
        try:
            self._loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self.sniffer: Optional[AsyncSniffer] = None

    def _packet_callback(self, packet):
        if not packet.haslayer(Ether):
            return
        parsed = None
        
        # Stateless demuxing based on transport layer hints
        if packet.haslayer(UDP):
            raw_payload = bytes(packet[UDP].payload)
            sport, dport = packet[UDP].sport, packet[UDP].dport
            if 10001 in (sport, dport):
                parsed = UbntDiscoveryDecoder.decode(raw_payload)
            elif 5678 in (sport, dport):
                parsed = MikrotikMndpDecoder.decode(raw_payload)
            elif 47808 in (sport, dport):
                parsed = BacnetIpDecoder.decode(raw_payload)
        else:
            # Defensive STP check for 802.3 LLC framing
            raw_payload = bytes(packet.payload)
            parsed = StpBpduDecoder.decode(raw_payload)

        if parsed:
            try:
                telemetry = DpiTelemetryPort(
                    protocol=parsed.get('protocol', 'UNKNOWN'),
                    mac_address=parsed.get('mac', '00:00:00:00:00:00'),
                    vendor=parsed.get('vendor', 'Unknown'),
                    device_type=parsed.get('type', 'unknown'),
                    model=parsed.get('model', ''),
                    firmware=parsed.get('firmware'),
                    hostname=parsed.get('hostname'),
                    archetype=parsed.get('archetype', 'UNKNOWN'),
                    kernel_turnaround_us=parsed.get('kernel_turnaround_us'),
                    kernel_prior_std_us=parsed.get('kernel_prior_std_us')
                )
                loop = self._loop
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.bus.push_telemetry(self.queue_name, telemetry.model_dump()),
                        loop
                    )
            except Exception as e:
                logger.error(f'DPI telemetry validation failed: {e}')

    def start(self):
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        self.sniffer = AsyncSniffer(iface=self.interface, prn=self._packet_callback, store=False)
        self.sniffer.start()
        logger.info(f'Passive DPI Adapter armed on {self.interface}')

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

