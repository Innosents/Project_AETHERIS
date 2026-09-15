"""
Project AETHERIS - Passive Enterprise Deep Packet Inspection (DPI) Decoders
Provides zero-packet, passive infrastructure intelligence by dissecting:
- Ubiquiti Discovery Protocol (UBNT - UDP 10001, v1 & v2)
- MikroTik Neighbor Discovery Protocol (MNDP - UDP 5678)
- BACnet/IP (UDP 47808)
- 802.1D / 802.1w / 802.1s Spanning Tree Protocol (STP / RSTP / MSTP BPDUs)

Parsed identities feed directly into Tier 2 Bayesian kernel turnaround priors (t_kernel)
and Layer 2 root path constraints in spatial_ledger.db.
Guarantees defensive binary slice safety and strict JSON round-trip invariance.
"""

import struct
import re
from typing import Any, Dict, Optional, Tuple, Union
from graphpath.core.probers.sanitization import sanitize_prober_payload, clean_ascii_string


# ==============================================================================
# Bayesian Turnaround Latency Prior Baselines
# ==============================================================================
# Hardware ASIC Fastpath (Ubiquiti USW, MikroTik CRS switches): t_kernel ~ N(4.0 us, 1.5^2)
KERNEL_PRIOR_ASIC_SWITCH_MEAN_US: float = 4.0
KERNEL_PRIOR_ASIC_SWITCH_STD_US: float = 1.5

# Router / AP Linux Stack (EdgeRouter, UniFi AP, RouterOS): t_kernel ~ N(35.0 us, 8.0^2)
KERNEL_PRIOR_ROUTER_AP_MEAN_US: float = 35.0
KERNEL_PRIOR_ROUTER_AP_STD_US: float = 8.0

# Slow Microcontroller Polling Loop (BACnet field controller): t_kernel ~ N(110.0 us, 25.0^2)
KERNEL_PRIOR_BACNET_CTRL_MEAN_US: float = 110.0
KERNEL_PRIOR_BACNET_CTRL_STD_US: float = 25.0


class UbntDiscoveryDecoder:
    """
    Decodes Ubiquiti Discovery Protocol (UBNT - UDP 10001) packets (Versions 1 & 2).
    Extracts hardware MAC, firmware version, hostname, and model identity.
    Classifies device role into switch, router, or wlan_ap to inject Bayesian t_kernel priors.
    """

    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if not payload or not isinstance(payload, (bytes, bytearray)):
            return None
        if len(payload) < 4:
            return None
        if payload[0] not in (1, 2):
            return None

        results: Dict[str, Any] = {
            "protocol": "UBNT",
            "vendor": "Ubiquiti Inc.",
            "type": "wlan_ap",
            "model": "Ubiquiti Device",
            "hostname": "",
            "firmware": "",
            "mac": "",
            "archetype": "ROUTER_AP_STACK",
            "kernel_turnaround_us": KERNEL_PRIOR_ROUTER_AP_MEAN_US,
            "kernel_prior_std_us": KERNEL_PRIOR_ROUTER_AP_STD_US,
        }

        pos = 4
        payload_len = len(payload)
        while pos + 3 <= payload_len:
            tlv_type = payload[pos]
            try:
                tlv_len = struct.unpack(">H", payload[pos + 1 : pos + 3])[0]
            except struct.error:
                break
            pos += 3

            if pos + tlv_len > payload_len:
                break
            val = payload[pos : pos + tlv_len]
            pos += tlv_len

            if tlv_type == 0x01 and tlv_len == 6:
                results["mac"] = ":".join(f"{b:02X}" for b in val)
            elif tlv_type == 0x03:
                results["firmware"] = clean_ascii_string(val.decode("utf-8", errors="ignore"))
            elif tlv_type == 0x0B:
                results["hostname"] = clean_ascii_string(val.decode("utf-8", errors="ignore"))
            elif tlv_type in (0x0C, 0x14, 0x15):
                model_str = clean_ascii_string(val.decode("utf-8", errors="ignore"))
                if model_str:
                    results["model"] = f"Ubiquiti {model_str}"
                    lower_model = model_str.lower()
                    if any(x in lower_model for x in ("switch", "usw", "edgeswitch")):
                        results["type"] = "switch"
                        results["archetype"] = "HARDWARE_ASIC_SWITCH"
                        results["kernel_turnaround_us"] = KERNEL_PRIOR_ASIC_SWITCH_MEAN_US
                        results["kernel_prior_std_us"] = KERNEL_PRIOR_ASIC_SWITCH_STD_US
                    elif any(x in lower_model for x in ("udm", "edgerouter", "gateway", "uxg")):
                        results["type"] = "router"
                        results["archetype"] = "ROUTER_AP_STACK"
                        results["kernel_turnaround_us"] = KERNEL_PRIOR_ROUTER_AP_MEAN_US
                        results["kernel_prior_std_us"] = KERNEL_PRIOR_ROUTER_AP_STD_US
                    elif any(x in lower_model for x in ("u6", "u7", "ap", "unifi", "airmax", "nanostation")):
                        results["type"] = "wlan_ap"
                        results["archetype"] = "ROUTER_AP_STACK"
                        results["kernel_turnaround_us"] = KERNEL_PRIOR_ROUTER_AP_MEAN_US
                        results["kernel_prior_std_us"] = KERNEL_PRIOR_ROUTER_AP_STD_US

        if not (results.get("mac") or results.get("hostname") or results.get("firmware")):
            return None

        return sanitize_prober_payload(results)


class MikrotikMndpDecoder:
    """
    Decodes MikroTik Neighbor Discovery Protocol (MNDP - UDP 5678) packets.
    Extracts MAC, Hostname/Identity, RouterOS Version, Platform/Board, and Architecture.
    Differentiates CRS switches from CCR/hEX routers to set Bayesian t_kernel priors.
    """

    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if not payload or not isinstance(payload, (bytes, bytearray)):
            return None
        if len(payload) < 4:
            return None

        results: Dict[str, Any] = {
            "protocol": "MNDP",
            "vendor": "MikroTik",
            "type": "router",
            "model": "MikroTik RouterOS Device",
            "hostname": "",
            "firmware": "",
            "mac": "",
            "architecture": "",
            "archetype": "ROUTER_AP_STACK",
            "kernel_turnaround_us": KERNEL_PRIOR_ROUTER_AP_MEAN_US,
            "kernel_prior_std_us": KERNEL_PRIOR_ROUTER_AP_STD_US,
        }

        pos = 0
        payload_len = len(payload)
        while pos + 4 <= payload_len:
            try:
                tlv_type, tlv_len = struct.unpack(">HH", payload[pos : pos + 4])
            except struct.error:
                break
            pos += 4

            if pos + tlv_len > payload_len:
                break
            val = payload[pos : pos + tlv_len]
            pos += tlv_len

            if tlv_type == 0x01 and tlv_len == 6:
                results["mac"] = ":".join(f"{b:02X}" for b in val)
            elif tlv_type == 0x05:
                results["hostname"] = clean_ascii_string(val.decode("utf-8", errors="ignore"))
            elif tlv_type == 0x07:
                fw = clean_ascii_string(val.decode("utf-8", errors="ignore"))
                results["firmware"] = f"RouterOS {fw}" if fw else ""
            elif tlv_type == 0x08:
                board = clean_ascii_string(val.decode("utf-8", errors="ignore"))
                results["model"] = f"MikroTik {board}"
                lower_board = board.lower()
                if "crs" in lower_board or "switch" in lower_board:
                    results["type"] = "switch"
                    results["archetype"] = "HARDWARE_ASIC_SWITCH"
                    results["kernel_turnaround_us"] = KERNEL_PRIOR_ASIC_SWITCH_MEAN_US
                    results["kernel_prior_std_us"] = KERNEL_PRIOR_ASIC_SWITCH_STD_US
                else:
                    results["type"] = "router"
                    results["archetype"] = "ROUTER_AP_STACK"
                    results["kernel_turnaround_us"] = KERNEL_PRIOR_ROUTER_AP_MEAN_US
                    results["kernel_prior_std_us"] = KERNEL_PRIOR_ROUTER_AP_STD_US
            elif tlv_type == 0x0A:
                results["architecture"] = clean_ascii_string(val.decode("utf-8", errors="ignore"))

        if not (results.get("mac") or results.get("hostname") or results.get("firmware")):
            return None

        return sanitize_prober_payload(results)


class BacnetIpDecoder:
    """
    Decodes BACnet/IP (UDP 47808) building automation frames.
    Dissects BVLC Header (Type 0x81, Functions 0x0A/0x0B/0x04) and NPDU routing.
    Distinguishes active field controller announcements (I-Am, I-Have) from workstation queries (Who-Is).
    Recovers 22-bit BACnet Device Instance IDs and assigns slow microcontroller priors (t_kernel ~ 110 us).
    """

    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if not payload or not isinstance(payload, (bytes, bytearray)):
            return None
        if len(payload) < 6:
            return None

        # Validate BVLC type 0x81
        if payload[0] != 0x81:
            return None

        bvlc_func = payload[1]
        try:
            bvlc_len = struct.unpack(">H", payload[2:4])[0]
        except struct.error:
            return None

        # Determine start of NPDU based on BVLC function
        if bvlc_func == 0x04:  # Forwarded-NPDU (has 4B IP + 2B Port origin header)
            npdu_pos = 10
        elif bvlc_func in (0x0A, 0x0B):  # Original-Unicast-NPDU or Original-Broadcast-NPDU
            npdu_pos = 4
        else:
            npdu_pos = 4

        if npdu_pos >= len(payload):
            return None

        npdu_version = payload[npdu_pos]
        if npdu_version != 0x01:
            return None

        if npdu_pos + 1 >= len(payload):
            return None
        npdu_ctrl = payload[npdu_pos + 1]
        pos = npdu_pos + 2

        # Handle DNET/DLEN/DADR and Hop Count (bit 5: 0x20)
        dnet: Optional[int] = None
        dadr: Optional[bytes] = None
        if npdu_ctrl & 0x20:
            if pos + 3 > len(payload):
                return None
            try:
                dnet = struct.unpack(">H", payload[pos : pos + 2])[0]
            except struct.error:
                return None
            dlen = payload[pos + 2]
            if pos + 3 + dlen + 1 > len(payload):
                return None
            dadr = payload[pos + 3 : pos + 3 + dlen]
            pos += 3 + dlen + 1  # 2B DNET + 1B DLEN + dlen DADR + 1B Hop Count

        # Handle SNET/SLEN/SADR (bit 3: 0x08)
        snet: Optional[int] = None
        sadr: Optional[bytes] = None
        if npdu_ctrl & 0x08:
            if pos + 3 > len(payload):
                return None
            try:
                snet = struct.unpack(">H", payload[pos : pos + 2])[0]
            except struct.error:
                return None
            slen = payload[pos + 2]
            if pos + 3 + slen > len(payload):
                return None
            sadr = payload[pos + 3 : pos + 3 + slen]
            pos += 3 + slen

        if pos >= len(payload):
            return None

        # Network layer message (bit 7: 0x80)
        if npdu_ctrl & 0x80:
            return sanitize_prober_payload({
                "protocol": "BACNET_IP",
                "service": "NetworkLayerMessage",
                "is_controller": False,
                "is_mstp_routed": False,
                "snet": snet,
                "sadr": sadr.hex() if sadr else "",
                "routed_device": None,
                "archetype": "WORKSTATION",
                "vendor": "BACnet Building Automation",
                "type": "workstation",
                "model": "BACnet Network Entity",
                "kernel_turnaround_us": None,
                "kernel_prior_std_us": None,
            })

        apdu_byte = payload[pos]
        apdu_type = (apdu_byte >> 4) & 0x0F

        is_mstp_routed = snet is not None
        sadr_hex = sadr.hex() if sadr else ""

        # APDU Type 1: Unconfirmed-Request-PDU (I-Am, Who-Is, I-Have)
        if apdu_type == 1:
            if pos + 1 >= len(payload):
                return None
            service_choice = payload[pos + 1]

            if service_choice == 0x00:
                # I-Am announcement
                dev_id: Optional[int] = None
                iam_pos = pos + 2
                if iam_pos + 5 <= len(payload) and payload[iam_pos] == 0xC4:
                    try:
                        raw_id = struct.unpack(">I", payload[iam_pos + 1 : iam_pos + 5])[0]
                        dev_id = raw_id & 0x3FFFFF  # 22-bit instance ID
                    except struct.error:
                        dev_id = None

                if is_mstp_routed:
                    # Layer 3 IP belongs to the BACnet/IP router; downstream controller is on MS/TP
                    routed_dev = {
                        "archetype": "BACNET_FIELD_CONTROLLER",
                        "kernel_turnaround_us": KERNEL_PRIOR_BACNET_CTRL_MEAN_US,
                        "kernel_prior_std_us": KERNEL_PRIOR_BACNET_CTRL_STD_US,
                        "snet": snet,
                        "sadr": sadr_hex,
                        "device_instance": dev_id,
                    }
                    return sanitize_prober_payload({
                        "protocol": "BACNET_IP",
                        "vendor": "BACnet Building Automation",
                        "type": "router",
                        "model": "BACnet/IP MS/TP Router",
                        "service": "I-Am",
                        "is_controller": False,
                        "is_mstp_routed": True,
                        "snet": snet,
                        "sadr": sadr_hex,
                        "device_instance": dev_id,
                        "routed_device": routed_dev,
                        "archetype": "ROUTER_AP_STACK",
                        "kernel_turnaround_us": KERNEL_PRIOR_ROUTER_AP_MEAN_US,
                        "kernel_prior_std_us": KERNEL_PRIOR_ROUTER_AP_STD_US,
                    })
                else:
                    model_desc = f"BACnet Device (ID: {dev_id})" if dev_id is not None else "BACnet Field Controller"
                    return sanitize_prober_payload({
                        "protocol": "BACNET_IP",
                        "vendor": "BACnet Building Automation",
                        "type": "iot_controller",
                        "model": model_desc,
                        "service": "I-Am",
                        "is_controller": True,
                        "is_mstp_routed": False,
                        "snet": None,
                        "sadr": "",
                        "device_instance": dev_id,
                        "routed_device": None,
                        "archetype": "BACNET_FIELD_CONTROLLER",
                        "kernel_turnaround_us": KERNEL_PRIOR_BACNET_CTRL_MEAN_US,
                        "kernel_prior_std_us": KERNEL_PRIOR_BACNET_CTRL_STD_US,
                    })

            elif service_choice == 0x08:
                # Who-Is discovery query from client/management workstation
                return sanitize_prober_payload({
                    "protocol": "BACNET_IP",
                    "vendor": "BACnet Building Automation",
                    "type": "workstation",
                    "model": "BACnet Management Workstation",
                    "service": "Who-Is",
                    "is_controller": False,
                    "is_mstp_routed": is_mstp_routed,
                    "snet": snet,
                    "sadr": sadr_hex,
                    "device_instance": None,
                    "routed_device": None,
                    "archetype": "WORKSTATION",
                    "kernel_turnaround_us": None,
                    "kernel_prior_std_us": None,
                })

            elif service_choice == 0x01:
                # I-Have announcement
                if is_mstp_routed:
                    routed_dev = {
                        "archetype": "BACNET_FIELD_CONTROLLER",
                        "kernel_turnaround_us": KERNEL_PRIOR_BACNET_CTRL_MEAN_US,
                        "kernel_prior_std_us": KERNEL_PRIOR_BACNET_CTRL_STD_US,
                        "snet": snet,
                        "sadr": sadr_hex,
                    }
                    return sanitize_prober_payload({
                        "protocol": "BACNET_IP",
                        "vendor": "BACnet Building Automation",
                        "type": "router",
                        "model": "BACnet/IP MS/TP Router",
                        "service": "I-Have",
                        "is_controller": False,
                        "is_mstp_routed": True,
                        "snet": snet,
                        "sadr": sadr_hex,
                        "device_instance": None,
                        "routed_device": routed_dev,
                        "archetype": "ROUTER_AP_STACK",
                        "kernel_turnaround_us": KERNEL_PRIOR_ROUTER_AP_MEAN_US,
                        "kernel_prior_std_us": KERNEL_PRIOR_ROUTER_AP_STD_US,
                    })
                else:
                    return sanitize_prober_payload({
                        "protocol": "BACNET_IP",
                        "vendor": "BACnet Building Automation",
                        "type": "iot_controller",
                        "model": "BACnet Field Controller",
                        "service": "I-Have",
                        "is_controller": True,
                        "is_mstp_routed": False,
                        "snet": None,
                        "sadr": "",
                        "device_instance": None,
                        "routed_device": None,
                        "archetype": "BACNET_FIELD_CONTROLLER",
                        "kernel_turnaround_us": KERNEL_PRIOR_BACNET_CTRL_MEAN_US,
                        "kernel_prior_std_us": KERNEL_PRIOR_BACNET_CTRL_STD_US,
                    })

        # APDU Type 2 or 3: ACK response from controller
        elif apdu_type in (2, 3):
            if is_mstp_routed:
                routed_dev = {
                    "archetype": "BACNET_FIELD_CONTROLLER",
                    "kernel_turnaround_us": KERNEL_PRIOR_BACNET_CTRL_MEAN_US,
                    "kernel_prior_std_us": KERNEL_PRIOR_BACNET_CTRL_STD_US,
                    "snet": snet,
                    "sadr": sadr_hex,
                }
                return sanitize_prober_payload({
                    "protocol": "BACNET_IP",
                    "vendor": "BACnet Building Automation",
                    "type": "router",
                    "model": "BACnet/IP MS/TP Router",
                    "service": "ACK",
                    "is_controller": False,
                    "is_mstp_routed": True,
                    "snet": snet,
                    "sadr": sadr_hex,
                    "device_instance": None,
                    "routed_device": routed_dev,
                    "archetype": "ROUTER_AP_STACK",
                    "kernel_turnaround_us": KERNEL_PRIOR_ROUTER_AP_MEAN_US,
                    "kernel_prior_std_us": KERNEL_PRIOR_ROUTER_AP_STD_US,
                })
            else:
                return sanitize_prober_payload({
                    "protocol": "BACNET_IP",
                    "vendor": "BACnet Building Automation",
                    "type": "iot_controller",
                    "model": "BACnet Field Controller",
                    "service": "ACK",
                    "is_controller": True,
                    "is_mstp_routed": False,
                    "snet": None,
                    "sadr": "",
                    "device_instance": None,
                    "routed_device": None,
                    "archetype": "BACNET_FIELD_CONTROLLER",
                    "kernel_turnaround_us": KERNEL_PRIOR_BACNET_CTRL_MEAN_US,
                    "kernel_prior_std_us": KERNEL_PRIOR_BACNET_CTRL_STD_US,
                })

        # APDU Type 0: Confirmed-Request
        elif apdu_type == 0:
            return sanitize_prober_payload({
                "protocol": "BACNET_IP",
                "vendor": "BACnet Building Automation",
                "type": "workstation",
                "model": "BACnet Client Host",
                "service": "Confirmed-Req",
                "is_controller": False,
                "is_mstp_routed": is_mstp_routed,
                "snet": snet,
                "sadr": sadr_hex,
                "device_instance": None,
                "routed_device": None,
                "archetype": "WORKSTATION",
                "kernel_turnaround_us": None,
                "kernel_prior_std_us": None,
            })

        return None


class StpBpduDecoder:
    """
    Decodes 802.1D / 802.1w / 802.1s Spanning Tree Protocol (STP / RSTP / MSTP) BPDUs.
    Strips LLC/SNAP framing (0x424203) if present.
    Decomposes 16-bit Bridge Priority into Base Priority (upper 4 bits) and SysID Extension/VLAN ID (lower 12 bits).
    Extracts Root Bridge MAC, Root Path Cost, Designated Bridge MAC, and Port ID.
    Asserts whether transmitting bridge is the Spanning Tree Root Bridge.
    Assigns hardware ASIC switch priors (t_kernel ~ 4.0 us).
    """

    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if not payload or not isinstance(payload, (bytes, bytearray)):
            return None

        # Strip 3-byte LLC/SNAP header (DSAP 0x42, SSAP 0x42, Control 0x03)
        if len(payload) >= 3 and payload[:3] == b"\x42\x42\x03":
            payload = payload[3:]

        if len(payload) < 35:
            return None

        try:
            proto_id, version, bpdu_type = struct.unpack(">HBB", payload[:4])
        except struct.error:
            return None

        if proto_id != 0:
            return None

        flags = payload[4]
        try:
            root_prio = struct.unpack(">H", payload[5:7])[0]
            root_base_priority = root_prio & 0xF000
            root_vlan_id = root_prio & 0x0FFF
            root_mac = ":".join(f"{b:02X}" for b in payload[7:13])
            root_path_cost = struct.unpack(">I", payload[13:17])[0]
            bridge_prio = struct.unpack(">H", payload[17:19])[0]
            bridge_base_priority = bridge_prio & 0xF000
            bridge_vlan_id = bridge_prio & 0x0FFF
            bridge_mac = ":".join(f"{b:02X}" for b in payload[19:25])
            port_id = struct.unpack(">H", payload[25:27])[0]
        except struct.error:
            return None

        is_root = (root_mac == bridge_mac)
        stp_ver_map = {0: "STP (802.1D)", 2: "RSTP (802.1w)", 3: "MSTP (802.1s)"}
        stp_ver_str = stp_ver_map.get(version, f"STP_v{version}")

        bpdu_type_str = (
            "TopologyChange"
            if bpdu_type == 0x80
            else ("RSTP" if bpdu_type == 0x02 else "Config")
        )

        return sanitize_prober_payload({
            "protocol": "STP_BPDU",
            "stp_version": stp_ver_str,
            "bpdu_type": bpdu_type_str,
            "root_bridge_mac": root_mac,
            "root_priority": root_prio,
            "root_base_priority": root_base_priority,
            "root_vlan_id": root_vlan_id,
            "vlan_id": root_vlan_id,
            "root_path_cost": root_path_cost,
            "bridge_mac": bridge_mac,
            "designated_bridge_mac": bridge_mac,
            "bridge_priority": bridge_prio,
            "bridge_base_priority": bridge_base_priority,
            "bridge_vlan_id": bridge_vlan_id,
            "port_id": port_id,
            "is_root_bridge": is_root,
            "tc_flag": bool(flags & 0x01),
            "mac": bridge_mac,
            "archetype": "HARDWARE_ASIC_SWITCH",
            "type": "switch",
            "vendor": "IEEE 802.1 Bridge",
            "model": f"{stp_ver_str} Bridge",
            "kernel_turnaround_us": KERNEL_PRIOR_ASIC_SWITCH_MEAN_US,
            "kernel_prior_std_us": KERNEL_PRIOR_ASIC_SWITCH_STD_US,
        })


class DpiDispatcher:
    """
    Central passive frame dispatcher routing raw payloads through specialized DPI decoders.
    Provides multi-port routing, LLC protocol demuxing, defensive heuristic fallback,
    and guaranteed recursive payload sanitization.
    """

    def __init__(self) -> None:
        self.ubnt_decoder = UbntDiscoveryDecoder()
        self.mndp_decoder = MikrotikMndpDecoder()
        self.bacnet_decoder = BacnetIpDecoder()
        self.stp_decoder = StpBpduDecoder()

    _default_instance: Optional["DpiDispatcher"] = None

    @classmethod
    def get_default_instance(cls) -> "DpiDispatcher":
        if cls._default_instance is None:
            cls._default_instance = cls()
        return cls._default_instance

    def dispatch(*args, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Dispatches raw packet payload to appropriate decoder based on port, ethertype,
        destination MAC, or protocol heuristics.
        Supports both instance call (dispatcher.dispatch(...)) and class call (DpiDispatcher.dispatch(...)),
        as well as sport/dport aliases.
        """
        if args and isinstance(args[0], DpiDispatcher):
            self = args[0]
            args = args[1:]
        else:
            self = DpiDispatcher.get_default_instance()
            if args and args[0] is DpiDispatcher:
                args = args[1:]

        payload = kwargs.pop("payload", None)
        if payload is None and args:
            payload = args[0]
            args = args[1:]

        src_port = kwargs.pop("src_port", None)
        dst_port = kwargs.pop("dst_port", None)
        sport = kwargs.pop("sport", None)
        dport = kwargs.pop("dport", None)
        ethertype = kwargs.pop("ethertype", None)
        dst_mac = kwargs.pop("dst_mac", None)

        s_port = src_port if src_port is not None else sport
        d_port = dst_port if dst_port is not None else dport

        return self._dispatch_impl(
            payload=payload,
            src_port=s_port,
            dst_port=d_port,
            ethertype=ethertype,
            dst_mac=dst_mac,
        )

    def _dispatch_impl(
        self,
        payload: bytes,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        ethertype: Optional[int] = None,
        dst_mac: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if not payload or not isinstance(payload, (bytes, bytearray)):
            return None
        data = bytes(payload)

        try:
            # 1. Spanning Tree Protocol (LLC framing, ethertype, raw Ethernet frame, or STP multicast destination)
            if len(data) >= 14 and data[:6] in (b"\x01\x80\xc2\x00\x00\x00", b"\x01\x80\xc2\x00\x00\x08", b"\x01\x80\xc2\x00\x00\x0e"):
                res = self.stp_decoder.decode(data[14:])
                if res:
                    return sanitize_prober_payload(res)

            if (
                data.startswith(b"\x42\x42\x03")
                or (dst_mac and dst_mac.upper() in ("01:80:C2:00:00:00", "01-80-C2-00-00-00"))
                or ethertype in (0x0026, 0x0027)
            ):
                res = self.stp_decoder.decode(data)
                if res:
                    return sanitize_prober_payload(res)

            # 2. Port-based dispatch
            ports = (src_port, dst_port)
            if 10001 in ports:
                res = self.ubnt_decoder.decode(data)
                if res:
                    return sanitize_prober_payload(res)
            if 5678 in ports:
                res = self.mndp_decoder.decode(data)
                if res:
                    return sanitize_prober_payload(res)
            if 47808 in ports:
                res = self.bacnet_decoder.decode(data)
                if res:
                    return sanitize_prober_payload(res)

            # 3. Defensive heuristic fallback
            if data.startswith(b"\x42\x42\x03") or (len(data) >= 35 and data[:2] == b"\x00\x00"):
                res = self.stp_decoder.decode(data)
                if res:
                    return sanitize_prober_payload(res)

            if len(data) >= 4 and data[0] in (1, 2):
                res = self.ubnt_decoder.decode(data)
                if res:
                    return sanitize_prober_payload(res)

            if len(data) >= 6 and data[0] == 0x81:
                res = self.bacnet_decoder.decode(data)
                if res:
                    return sanitize_prober_payload(res)

            if len(data) >= 4:
                res = self.mndp_decoder.decode(data)
                if res:
                    return sanitize_prober_payload(res)

        except Exception:
            return None

        return None
