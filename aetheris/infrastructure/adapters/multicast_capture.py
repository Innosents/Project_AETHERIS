"""
Project AETHERIS - Multicast Capture Infrastructure Adapter
Passively sniffs and decodes mDNS (UDP 5353) and SSDP (UDP 1900) beacons,
publishing validated MulticastTelemetryPort instances directly to Memurai.
"""

import asyncio
import logging
import re
from typing import Optional, List, Any

from scapy.all import AsyncSniffer, Ether, IP, IPv6, UDP, DNS, Raw
from aetheris.core.ports.l2_multicast_inbound import MulticastTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.multicast_capture")


class MulticastCaptureAdapter:
    """
    Decoupled passive L2/L3 multicast listener streaming validated telemetry
    to 'aetheris:telemetry:multicast_intel'.
    """

    def __init__(
        self,
        interface: str,
        event_bus: MemuraiEventBus,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.interface = interface
        self.bus = event_bus
        self.queue_name = "aetheris:telemetry:multicast_intel"
        try:
            self._loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self.sniffer: Optional[AsyncSniffer] = None

    def _packet_callback(self, packet: Any) -> None:
        """Processes mDNS and SSDP multicast frames into MulticastTelemetryPort."""
        mac_src = packet[Ether].src if packet.haslayer(Ether) else getattr(packet, "src", "00:00:00:00:00:00")
        if not mac_src or mac_src == "00:00:00:00:00:00":
            return

        ip_src = "0.0.0.0"
        if packet.haslayer(IP):
            ip_src = packet[IP].src
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src

        protocol: Optional[str] = None
        discovered_services: List[str] = []
        server_header: Optional[str] = None
        hostname: Optional[str] = None

        # 1. mDNS Parsing (UDP 5353)
        if (packet.haslayer(UDP) and (packet[UDP].sport == 5353 or packet[UDP].dport == 5353)) or packet.haslayer(DNS):
            protocol = "MDNS"
            if packet.haslayer(DNS) and hasattr(packet[DNS], "an") and packet[DNS].an:
                try:
                    for rr in packet[DNS].an:
                        if hasattr(rr, "rrname"):
                            s_name = rr.rrname.decode("utf-8", errors="ignore") if isinstance(rr.rrname, bytes) else str(rr.rrname or "")
                            s_data = rr.rdata.decode("utf-8", errors="ignore") if hasattr(rr, "rdata") and isinstance(rr.rdata, bytes) else str(getattr(rr, "rdata", "") or "")
                            if s_name:
                                discovered_services.append(s_name)
                                if ".local" in s_name.lower() and not hostname:
                                    hostname = s_name.rstrip(".")
                            if s_data:
                                discovered_services.append(s_data)
                                if ".local" in s_data.lower() and not hostname:
                                    hostname = s_data.rstrip(".")

                        curr = getattr(rr, "payload", None)
                        while curr and hasattr(curr, "rrname"):
                            c_name = curr.rrname.decode("utf-8", errors="ignore") if isinstance(curr.rrname, bytes) else str(curr.rrname or "")
                            c_data = curr.rdata.decode("utf-8", errors="ignore") if hasattr(curr, "rdata") and isinstance(curr.rdata, bytes) else str(getattr(curr, "rdata", "") or "")
                            if c_name:
                                discovered_services.append(c_name)
                            if c_data:
                                discovered_services.append(c_data)
                            curr = getattr(curr, "payload", None)
                except Exception as e:
                    logger.debug(f"mDNS parsing error: {e}")

        # 2. SSDP Parsing (UDP 1900)
        elif (packet.haslayer(UDP) and (packet[UDP].sport == 1900 or packet[UDP].dport == 1900)) or packet.haslayer(Raw):
            protocol = "SSDP"
            if packet.haslayer(Raw):
                try:
                    raw_payload = packet[Raw].load
                    payload = raw_payload.decode("utf-8", errors="ignore") if isinstance(raw_payload, bytes) else str(raw_payload or "")
                    server_match = re.search(r"(?i)\b(?:Server|User-Agent):\s*([^\r\n]+)", payload)
                    if server_match:
                        server_header = server_match.group(1).strip()
                    for st_match in re.finditer(r"(?i)\b(?:ST|USN|NT):\s*([^\r\n]+)", payload):
                        discovered_services.append(st_match.group(1).strip())
                except Exception as e:
                    logger.debug(f"SSDP parsing error: {e}")

        if protocol:
            try:
                unique_services = list(dict.fromkeys(discovered_services))
                telemetry = MulticastTelemetryPort(
                    mac_address=mac_src,
                    ip_address=ip_src,
                    protocol=protocol,
                    discovered_services=unique_services,
                    server_header=server_header,
                    hostname=hostname,
                )
                loop = self._loop
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.bus.push_telemetry(self.queue_name, telemetry.model_dump()),
                        loop,
                    )
            except Exception as e:
                logger.error(f"Multicast telemetry validation failed: {e}")

    def start(self) -> None:
        """Starts asynchronous packet capture on interface."""
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter="udp port 5353 or udp port 1900",
            prn=self._packet_callback,
            store=0,
        )
        self.sniffer.start()
        logger.info(f"Multicast Capture Adapter armed on {self.interface}")

    def stop(self) -> None:
        """Terminates active packet sniffer."""
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.debug(f"Error stopping sniffer: {e}")
            self.sniffer = None

    def __enter__(self) -> "MulticastCaptureAdapter":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
