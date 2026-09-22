import asyncio
import logging
from typing import Optional
from scapy.all import AsyncSniffer, UDP
from aetheris.core.ports.dhcp_inbound import DhcpTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus
from aetheris.core.fingerprinting.dhcp_parser import parse_dhcp_packet

logger = logging.getLogger('aetheris.adapters.dhcp_capture')

class DhcpCaptureAdapter:
    def __init__(self, interface: str, event_bus: MemuraiEventBus, loop: Optional[asyncio.AbstractEventLoop] = None):
        self.interface = interface
        self.bus = event_bus
        self.queue_name = 'aetheris:telemetry:dhcp_intelligence'
        try:
            self._loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self.sniffer: Optional[AsyncSniffer] = None

    def _packet_callback(self, packet):
        if not packet.haslayer(UDP) or packet[UDP].sport not in (67, 68):
            return
            
        parsed = parse_dhcp_packet(bytes(packet))
        if parsed:
            try:
                telemetry = DhcpTelemetryPort(
                    mac_address=parsed.get('mac', '00:00:00:00:00:00'),
                    ip_address=parsed.get('ip', '0.0.0.0'),
                    os_profile=parsed.get('os_profile', 'UNKNOWN'),
                    confidence=float(parsed.get('confidence', 50.0)),
                    prl_hash=parsed.get('prl_hash', ''),
                    hostname=parsed.get('hostname'),
                    evidence=parsed.get('evidence', '')
                )
                loop = self._loop
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.bus.push_telemetry(self.queue_name, telemetry.model_dump()),
                        loop
                    )
            except Exception as e:
                logger.error(f'DHCP payload validation failed: {e}')

    def start(self):
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter='udp and (port 67 or port 68)',
            prn=self._packet_callback,
            store=False
        )
        self.sniffer.start()
        logger.info(f'DHCP Capture Adapter armed on {self.interface}')

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

