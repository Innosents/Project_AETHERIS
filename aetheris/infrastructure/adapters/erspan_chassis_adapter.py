import asyncio
import logging
from typing import Optional
from scapy.all import AsyncSniffer
from scapy.layers.l2 import GRE, Ether
from scapy.contrib.erspan import ERSPAN_II, ERSPAN_III
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPlatform, CDPMsgSoftwareVersion, CDPMsgPortID
from scapy.contrib.lldp import LLDPDU, LLDPDUChassisID, LLDPDUSystemName, LLDPDUSystemDescription, LLDPDUPortID
from aetheris.core.ports.l2_chassis_inbound import ChassisTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger('aetheris.adapters.erspan_chassis')

class ErspanChassisAdapter:
    def __init__(self, interface: str, ingestion_ip: str, event_bus: MemuraiEventBus, loop: Optional[asyncio.AbstractEventLoop] = None):
        self.interface = interface
        self.ingestion_ip = ingestion_ip
        self.bus = event_bus
        self.queue_name = 'aetheris:telemetry:chassis_intel'
        try:
            self._loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self.sniffer: Optional[AsyncSniffer] = None

    def _frame_callback(self, packet) -> None:
        raw_port, raw_id = b'', b''
        tlvs = {'hostname': None, 'platform': None, 'os_version': None, 'port_id': None, 'chassis_mac': None}
        protocol = None
        mac_src = None

        if packet.haslayer(CDPv2_HDR):
            mac_src, protocol = packet.src, 'CDP'
            layer = packet[CDPv2_HDR].payload
            while layer:
                if isinstance(layer, CDPMsgDeviceID): tlvs['hostname'] = layer.val.decode(errors='ignore')
                elif isinstance(layer, CDPMsgPlatform): tlvs['platform'] = layer.val.decode(errors='ignore')
                elif isinstance(layer, CDPMsgSoftwareVersion): tlvs['os_version'] = layer.val.decode(errors='ignore').replace('\n', ' ')
                elif isinstance(layer, CDPMsgPortID): tlvs['port_id'] = layer.iface.decode(errors='ignore')
                layer = layer.payload if hasattr(layer, 'payload') else None

        elif packet.haslayer(LLDPDU):
            mac_src, protocol = packet.src, 'LLDP'
            layer = packet[LLDPDU].payload
            while layer:
                if isinstance(layer, LLDPDUSystemName): tlvs['hostname'] = layer.system_name.decode(errors='ignore')
                elif isinstance(layer, LLDPDUSystemDescription): tlvs['os_version'] = layer.description.decode(errors='ignore').replace('\n', ' ')
                elif isinstance(layer, LLDPDUPortID): raw_port = getattr(layer, 'id', b'')
                elif isinstance(layer, LLDPDUChassisID) and getattr(layer, 'subtype', 0) == 4: raw_id = getattr(layer, 'id', b'')
                layer = layer.payload if hasattr(layer, 'payload') else None

            tlvs['port_id'] = raw_port.decode(errors='ignore') if isinstance(raw_port, bytes) else str(raw_port) or None
            tlvs['chassis_mac'] = ':'.join(f'{b:02x}' for b in raw_id) if isinstance(raw_id, bytes) else (str(raw_id) or None)

        if protocol and mac_src:
            try:
                telemetry = ChassisTelemetryPort(mac_address=mac_src, protocol=protocol, **tlvs)
                loop = self._loop
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(self.bus.push_telemetry(self.queue_name, telemetry.model_dump()), loop)
            except Exception as e:
                logger.error(f'Chassis telemetry validation failed: {e}')

    def _erspan_wrapper(self, packet) -> None:
        if not packet.haslayer(GRE): return
        inner_frame = packet[ERSPAN_II].payload if packet.haslayer(ERSPAN_II) else (packet[ERSPAN_III].payload if packet.haslayer(ERSPAN_III) else packet[GRE].payload)
        if isinstance(inner_frame, Ether):
            self._frame_callback(inner_frame)

    def start(self):
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        bpf_filter = f'ip proto 47 and dst host {self.ingestion_ip}' if self.ingestion_ip else 'ip proto 47'
        self.sniffer = AsyncSniffer(iface=self.interface, filter=bpf_filter, prn=self._erspan_wrapper, store=0)
        self.sniffer.start()
        logger.info(f'ERSPAN Chassis Adapter armed on {self.interface} for {self.ingestion_ip}')

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

