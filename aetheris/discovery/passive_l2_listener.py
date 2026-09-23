"""
Project AETHERIS - Passive CDP & LLDP Topology Listener
Passively captures Layer 2 multicast frames to map switch-to-switch risers,
management SVIs, and trunk link hierarchies without administrative credentials.
"""

from typing import Dict, Any, Optional, Callable, List
import threading
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.sendrecv import AsyncSniffer
from scapy.contrib.lldp import (
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUSystemName,
    LLDPDUManagementAddress,
)
from scapy.contrib.cdp import (
    CDPv2_HDR,
    CDPMsgDeviceID,
    CDPMsgPortID,
    CDPMsgAddr,
    CDPMsgNativeVLAN,
    CDPAddrRecordIPv4,
)
from aetheris.core.ports.passive_l2_listener_port import (
    PassiveL2ListenerPort,
    L2SwitchTelemetryRecord,
    L2ListenerSummary,
    _MappingCompatibleModel,
)

LLDP_MULTICAST_MAC = "01:80:c2:00:00:0e"
CDP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"


def _extract_raw_mac(frame: Any) -> Optional[str]:
    """Safely extracts raw source MAC address string from an Ethernet frame."""
    if hasattr(frame, "haslayer") and frame.haslayer(Ether):
        try:
            eth = frame[Ether]
            if hasattr(eth, "src") and isinstance(eth.src, str):
                return eth.src
        except Exception:
            pass
    return None


class PassiveL2TopologyListener(PassiveL2ListenerPort):
    def __init__(self, on_switch_discovered: Optional[Callable[[Any], None]] = None):
        self.on_switch_discovered = on_switch_discovered
        self.discovered_switches: Dict[str, L2SwitchTelemetryRecord] = {}
        self.discovered_trunks: Dict[str, Dict[str, Any]] = {}
        self._sniffer: Optional[AsyncSniffer] = None
        self._running: bool = False

    def parse_lldp_frame(self, frame: Packet) -> Optional[L2SwitchTelemetryRecord]:
        """Extracts topology, chassis, and management metadata from an 802.1AB LLDPDU frame."""
        telemetry: Dict[str, Any] = {
            "protocol": "LLDP",
            "chassis_id": None,
            "system_name": None,
            "port_id": None,
            "management_ip": None,
            "raw_mac": _extract_raw_mac(frame),
        }

        # Traverse every child layer attached to the packet
        curr = frame
        while curr:
            if isinstance(curr, LLDPDUChassisID):
                val = getattr(curr, "id", None)
                telemetry["chassis_id"] = val.decode(errors="ignore") if isinstance(val, bytes) else (str(val) if val is not None and isinstance(val, str) else None)
            elif isinstance(curr, LLDPDUSystemName):
                val = getattr(curr, "system_name", None)
                telemetry["system_name"] = val.decode(errors="ignore") if isinstance(val, bytes) else (str(val) if val is not None and isinstance(val, str) else None)
            elif isinstance(curr, LLDPDUPortID):
                val = getattr(curr, "id", None)
                telemetry["port_id"] = val.decode(errors="ignore") if isinstance(val, bytes) else (str(val) if val is not None and isinstance(val, str) else None)
            elif isinstance(curr, LLDPDUManagementAddress):
                try:
                    raw_addr = getattr(curr, "management_address", None)
                    if isinstance(raw_addr, bytes) and len(raw_addr) >= 4:
                        telemetry["management_ip"] = ".".join(str(b) for b in raw_addr[:4])
                    elif isinstance(raw_addr, str):
                        telemetry["management_ip"] = raw_addr
                except Exception:
                    pass

            curr = curr.payload if hasattr(curr, "payload") and curr.payload else None

        switch_id = telemetry["system_name"] or telemetry["chassis_id"] or telemetry["raw_mac"]
        if not switch_id:
            return None

        telemetry["switch_id"] = switch_id
        return L2SwitchTelemetryRecord(**telemetry)

    def parse_cdp_frame(self, frame: Packet) -> Optional[L2SwitchTelemetryRecord]:
        """Extracts topology, device, and SVI metadata from a Cisco Discovery Protocol frame."""
        telemetry: Dict[str, Any] = {
            "protocol": "CDP",
            "chassis_id": None,
            "system_name": None,
            "port_id": None,
            "management_ip": None,
            "native_vlan": None,
            "raw_mac": _extract_raw_mac(frame),
        }

        curr = frame
        while curr:
            if isinstance(curr, CDPMsgDeviceID):
                # Scapy CDP uses 'msgdeviceid' or 'val' depending on exact scapy build
                val = getattr(curr, "msgdeviceid", None) or getattr(curr, "val", b"")
                dev_id = val.decode(errors="ignore") if isinstance(val, bytes) else (str(val) if val is not None and isinstance(val, str) else None)
                telemetry["system_name"] = dev_id
                telemetry["chassis_id"] = dev_id
            elif isinstance(curr, CDPMsgPortID):
                val = getattr(curr, "iface", b"")
                telemetry["port_id"] = val.decode(errors="ignore") if isinstance(val, bytes) else (str(val) if val is not None and isinstance(val, str) else None)
            elif isinstance(curr, CDPMsgNativeVLAN):
                vlan_val = getattr(curr, "vlan", None)
                if isinstance(vlan_val, int):
                    telemetry["native_vlan"] = vlan_val
            elif isinstance(curr, CDPMsgAddr):
                addr_list = getattr(curr, "addr", [])
                if isinstance(addr_list, list):
                    for addr_rec in addr_list:
                        if isinstance(addr_rec, CDPAddrRecordIPv4):
                            telemetry["management_ip"] = getattr(addr_rec, "addr", None)

            curr = curr.payload if hasattr(curr, "payload") and curr.payload else None

        switch_id = telemetry["system_name"] or telemetry["raw_mac"]
        if not switch_id:
            return None

        telemetry["switch_id"] = switch_id
        return L2SwitchTelemetryRecord(**telemetry)

    def process_packet(self, packet: Packet) -> Optional[L2SwitchTelemetryRecord]:
        """Inspects incoming frame; returns normalized switch telemetry if CDP/LLDP matched."""
        if not hasattr(packet, "haslayer") or not packet.haslayer(Ether):
            return None

        dst_mac = str(packet[Ether].dst).lower() if hasattr(packet[Ether], "dst") else ""
        extracted: Optional[L2SwitchTelemetryRecord] = None

        if dst_mac == LLDP_MULTICAST_MAC or packet.haslayer(LLDPDU) or packet.haslayer(LLDPDUChassisID):
            extracted = self.parse_lldp_frame(packet)
        elif dst_mac == CDP_MULTICAST_MAC or packet.haslayer(CDPv2_HDR) or packet.haslayer(CDPMsgDeviceID):
            extracted = self.parse_cdp_frame(packet)

        if extracted:
            sw_id = extracted.switch_id
            self.discovered_switches[sw_id] = extracted
            if self.on_switch_discovered:
                self.on_switch_discovered(extracted)

        return extracted

    def get_summary(self) -> L2ListenerSummary:
        """Returns snapshot of current discovered Layer 2 switch topology metadata."""
        protocols = sorted(list({rec.protocol for rec in self.discovered_switches.values() if rec.protocol}))
        return L2ListenerSummary(
            discovered_count=len(self.discovered_switches),
            switches=dict(self.discovered_switches),
            protocols_observed=protocols,
        )

    def start_listening(self, interface: Optional[str] = None, bpf_filter: str = "ether dst 01:80:c2:00:00:0e or ether dst 01:00:0c:cc:cc:cc or ether proto 0x88cc") -> None:
        """Starts asynchronous zero-copy BPF sniffer for 802.1AB LLDP and Cisco CDP frames."""
        if self._sniffer and self._sniffer.running:
            return

        self._running = True
        self._sniffer = AsyncSniffer(
            iface=interface,
            filter=bpf_filter,
            prn=self.process_packet,
            store=False
        )
        self._sniffer.start()

    def stop_listening(self) -> None:
        """Stops asynchronous listener."""
        self._running = False
        if self._sniffer and self._sniffer.running:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None


__all__ = [
    "PassiveL2TopologyListener",
    "PassiveL2ListenerPort",
    "L2SwitchTelemetryRecord",
    "L2ListenerSummary",
    "LLDP_MULTICAST_MAC",
    "CDP_MULTICAST_MAC",
    "_MappingCompatibleModel",
]