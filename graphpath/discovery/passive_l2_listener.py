"""
GraphPath Passive CDP & LLDP Topology Listener
Passively captures Layer 2 multicast frames to map switch-to-switch risers,
management SVIs, and trunk link hierarchies without administrative credentials.
"""

from typing import Dict, Any, Optional, Callable
from scapy.packet import Packet
from scapy.layers.l2 import Ether
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

LLDP_MULTICAST_MAC = "01:80:c2:00:00:0e"
CDP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"


class PassiveL2TopologyListener:
    def __init__(self, on_switch_discovered: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.on_switch_discovered = on_switch_discovered
        self.discovered_switches: Dict[str, Dict[str, Any]] = {}
        self.discovered_trunks: Dict[str, Dict[str, Any]] = {}

    def parse_lldp_frame(self, frame: Packet) -> Optional[Dict[str, Any]]:
        """Extracts topology, chassis, and management metadata from an 802.1AB LLDPDU frame."""
        telemetry: Dict[str, Any] = {
            "protocol": "LLDP",
            "chassis_id": None,
            "system_name": None,
            "port_id": None,
            "management_ip": None,
            "raw_mac": frame[Ether].src if frame.haslayer(Ether) else None,
        }

        # Traverse every child layer attached to the packet
        curr = frame
        while curr:
            if isinstance(curr, LLDPDUChassisID):
                val = getattr(curr, "id", None)
                telemetry["chassis_id"] = val.decode(errors="ignore") if isinstance(val, bytes) else str(val)
            elif isinstance(curr, LLDPDUSystemName):
                val = getattr(curr, "system_name", None)
                telemetry["system_name"] = val.decode(errors="ignore") if isinstance(val, bytes) else str(val)
            elif isinstance(curr, LLDPDUPortID):
                val = getattr(curr, "id", None)
                telemetry["port_id"] = val.decode(errors="ignore") if isinstance(val, bytes) else str(val)
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
        return telemetry

    def parse_cdp_frame(self, frame: Packet) -> Optional[Dict[str, Any]]:
        """Extracts topology, device, and SVI metadata from a Cisco Discovery Protocol frame."""
        telemetry: Dict[str, Any] = {
            "protocol": "CDP",
            "chassis_id": None,
            "system_name": None,
            "port_id": None,
            "management_ip": None,
            "native_vlan": None,
            "raw_mac": frame[Ether].src if frame.haslayer(Ether) else None,
        }

        curr = frame
        while curr:
            if isinstance(curr, CDPMsgDeviceID):
                # Scapy CDP uses 'msgdeviceid' or 'val' depending on exact scapy build
                val = getattr(curr, "msgdeviceid", None) or getattr(curr, "val", b"")
                dev_id = val.decode(errors="ignore") if isinstance(val, bytes) else str(val)
                telemetry["system_name"] = dev_id
                telemetry["chassis_id"] = dev_id
            elif isinstance(curr, CDPMsgPortID):
                val = getattr(curr, "iface", b"")
                telemetry["port_id"] = val.decode(errors="ignore") if isinstance(val, bytes) else str(val)
            elif isinstance(curr, CDPMsgNativeVLAN):
                telemetry["native_vlan"] = getattr(curr, "vlan", None)
            elif isinstance(curr, CDPMsgAddr):
                addr_list = getattr(curr, "addr", [])
                for addr_rec in addr_list:
                    if isinstance(addr_rec, CDPAddrRecordIPv4):
                        telemetry["management_ip"] = addr_rec.addr

            curr = curr.payload if hasattr(curr, "payload") and curr.payload else None

        switch_id = telemetry["system_name"] or telemetry["raw_mac"]
        if not switch_id:
            return None

        telemetry["switch_id"] = switch_id
        return telemetry

    def process_packet(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Inspects incoming frame; returns normalized switch telemetry if CDP/LLDP matched."""
        if not packet.haslayer(Ether):
            return None

        dst_mac = packet[Ether].dst.lower()
        extracted: Optional[Dict[str, Any]] = None

        if dst_mac == LLDP_MULTICAST_MAC or packet.haslayer(LLDPDU) or packet.haslayer(LLDPDUChassisID):
            extracted = self.parse_lldp_frame(packet)
        elif dst_mac == CDP_MULTICAST_MAC or packet.haslayer(CDPv2_HDR) or packet.haslayer(CDPMsgDeviceID):
            extracted = self.parse_cdp_frame(packet)

        if extracted:
            sw_id = extracted["switch_id"]
            self.discovered_switches[sw_id] = extracted
            if self.on_switch_discovered:
                self.on_switch_discovered(extracted)

        return extracted