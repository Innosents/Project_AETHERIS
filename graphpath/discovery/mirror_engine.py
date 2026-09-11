"""
GraphPath Port Mirroring (SPAN/RSPAN/ERSPAN) & Frame Ingestion Engine
Handles:
 - Promiscuous Network Interface packet capture & Ring Buffering
 - 802.1Q & 802.1ad (QinQ) Multi-VLAN Tag Extraction
 - ERSPAN Type II / III (GRE IP Proto 47) Decapsulation
 - L2/L3/L4 Protocol Demuxing and DPI Stream Hand-off
"""

import socket
import struct
import threading
import time
import ipaddress
from typing import Dict, Any, List, Optional, Tuple, Callable
from graphpath.discovery.dpi_parser import DpiParser

def _is_private_ip(ip_str: Optional[str]) -> bool:
    """Validates if an IP is a valid private/local RFC1918, Link-Local, CGNAT, or ULA IPv6 address."""
    if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255"):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_unspecified:
            return False
        if ip_obj.is_private:
            return True
        if ip_obj.version == 4:
            # Check CGNAT (100.64.0.0/10)
            if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
                return True
        return False
    except ValueError:
        return False


class VlanTagExtractor:
    """Extracts 802.1Q and 802.1ad VLAN tags from Ethernet frames."""

    @staticmethod
    def extract_vlan(frame: bytes) -> Tuple[Optional[int], int, bytes]:
        """
        Parses Ethernet header and any 802.1Q/802.1ad tag.
        Returns: (vlan_id, ethertype, payload)
        """
        if len(frame) < 14:
            return None, 0, frame

        # Dest MAC (6B) + Src MAC (6B) + EtherType (2B)
        ethertype = struct.unpack(">H", frame[12:14])[0]
        pos = 14
        vlan_id = None

        # 802.1Q (0x8100) or 802.1ad QinQ (0x88A8 / 0x9100)
        while ethertype in (0x8100, 0x88A8, 0x9100) and pos + 4 <= len(frame):
            tci = struct.unpack(">H", frame[pos:pos + 2])[0]
            vlan_id = tci & 0x0FFF  # 12-bit VID
            ethertype = struct.unpack(">H", frame[pos + 2:pos + 4])[0]
            pos += 4

        return vlan_id, ethertype, frame[pos:]


class ErspanDecapsulator:
    """Decapsulates ERSPAN Type II and Type III (GRE IP Protocol 47) packets."""

    @staticmethod
    def decapsulate(ip_payload: bytes) -> Optional[bytes]:
        """
        Takes raw IP payload of an IP protocol 47 (GRE) packet and strips GRE/ERSPAN headers.
        Returns the original inner Ethernet frame.
        """
        if len(ip_payload) < 8:
            return None

        try:
            flags, proto = struct.unpack(">HH", ip_payload[:4])
            pos = 4

            # Check if Sequence Number Present (bit 12: 0x1000)
            if flags & 0x1000:
                pos += 4
            # Check if Key Present (bit 13: 0x2000)
            if flags & 0x2000:
                pos += 4
            # Check if Checksum Present (bit 15: 0x8000) or Routing
            if flags & 0x8000 or flags & 0x4000:
                pos += 4

            # ERSPAN Type II (GRE Proto 0x88BE) -> 8-byte ERSPAN header
            if proto == 0x88BE:
                pos += 8
                if pos <= len(ip_payload):
                    return ip_payload[pos:]
            # ERSPAN Type III (GRE Proto 0x22EB) -> 12 or 20-byte ERSPAN header
            elif proto == 0x22EB:
                pos += 12
                if pos <= len(ip_payload):
                    return ip_payload[pos:]
            # Standard Transparent Ethernet Bridging (GRE Proto 0x6558)
            elif proto == 0x6558:
                if pos <= len(ip_payload):
                    return ip_payload[pos:]
        except Exception:
            pass

        return None


class SpanCaptureEngine:
    """
    Ingests mirrored SPAN / ERSPAN / TAP packets, extracts L2/L3/L4 headers,
    runs Deep Packet Inspection (DPI), and updates node discovery and traffic flows.
    """

    def __init__(self, interface: str = None, on_node_discovered: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.interface = interface
        self.on_node_discovered = on_node_discovered
        self._running = False
        self._lock = threading.Lock()
        self.stats = {
            "packets_captured": 0,
            "bytes_captured": 0,
            "vlans_discovered": set(),
            "protocols_detected": {},
            "active_hosts": set()
        }

    def process_raw_frame(self, frame: bytes) -> Dict[str, Any]:
        """
        Decodes a raw Ethernet frame, handles 802.1Q tags, ERSPAN GRE decapsulation,
        extracts L3/L4 conversation flows, and runs DPI protocol inspection.
        """
        with self._lock:
            self.stats["packets_captured"] += 1
            self.stats["bytes_captured"] += len(frame)

        if len(frame) < 14:
            return {}

        dst_mac = ":".join(f"{b:02X}" for b in frame[0:6])
        src_mac = ":".join(f"{b:02X}" for b in frame[6:12])

        # 1. 802.1Q VLAN Tag Extraction
        vlan_id, ethertype, payload = VlanTagExtractor.extract_vlan(frame)
        if vlan_id is not None:
            with self._lock:
                self.stats["vlans_discovered"].add(vlan_id)

        flow_data: Dict[str, Any] = {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "vlan_id": vlan_id,
            "ethertype": ethertype,
            "telemetry": {}
        }

        # 2. ARP Processing (EtherType 0x0806)
        if ethertype == 0x0806 and len(payload) >= 28:
            hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack(">HHBBH", payload[:8])
            if hw_len == 6 and proto_len == 4:
                sender_mac = ":".join(f"{b:02X}" for b in payload[8:14])
                sender_ip = ".".join(str(b) for b in payload[14:18])
                target_ip = ".".join(str(b) for b in payload[24:28])

                flow_data["src_ip"] = sender_ip
                flow_data["dst_ip"] = target_ip
                flow_data["proto"] = "ARP"
                flow_data["opcode"] = "REQUEST" if opcode == 1 else ("REPLY" if opcode == 2 else str(opcode))

                with self._lock:
                    if _is_private_ip(sender_ip):
                        self.stats["active_hosts"].add(sender_ip)
                    self.stats["protocols_detected"]["ARP"] = self.stats["protocols_detected"].get("ARP", 0) + 1

                if self.on_node_discovered and _is_private_ip(sender_ip):
                    self.on_node_discovered({
                        "ip": sender_ip,
                        "mac": sender_mac,
                        "vlan_id": vlan_id,
                        "discovery_method": "mirrored_span_arp"
                    })
                return flow_data

        # 3. IPv4 Processing (EtherType 0x0800)
        elif ethertype == 0x0800 and len(payload) >= 20:
            version_ihl = payload[0]
            ihl = (version_ihl & 0x0F) * 4
            ip_proto = payload[9]
            src_ip = ".".join(str(b) for b in payload[12:16])
            dst_ip = ".".join(str(b) for b in payload[16:20])

            flow_data["src_ip"] = src_ip
            flow_data["dst_ip"] = dst_ip

            with self._lock:
                if _is_private_ip(src_ip):
                    self.stats["active_hosts"].add(src_ip)
                if _is_private_ip(dst_ip):
                    self.stats["active_hosts"].add(dst_ip)

            # Check for ERSPAN GRE (IP Protocol 47)
            if ip_proto == 47:
                inner_frame = ErspanDecapsulator.decapsulate(payload[ihl:])
                if inner_frame:
                    return self.process_raw_frame(inner_frame)

            # TCP (Protocol 6)
            if ip_proto == 6 and len(payload) >= ihl + 20:
                tcp_hdr = payload[ihl:ihl + 20]
                src_port, dst_port, _, _, offset_flags = struct.unpack(">HHIIH", tcp_hdr[:14])
                tcp_data_offset = ((offset_flags >> 12) & 0x0F) * 4
                app_payload = payload[ihl + tcp_data_offset:]

                flow_data["proto"] = "TCP"
                flow_data["src_port"] = src_port
                flow_data["dst_port"] = dst_port

                with self._lock:
                    self.stats["protocols_detected"]["TCP"] = self.stats["protocols_detected"].get("TCP", 0) + 1

                # Deep Packet Inspection
                dpi_res = DpiParser.parse_payload(app_payload, src_port, dst_port, "TCP")
                if dpi_res:
                    flow_data["telemetry"] = dpi_res
                    self._dispatch_telemetry(src_ip, src_mac, dst_ip, vlan_id, dpi_res)

            # UDP (Protocol 17)
            elif ip_proto == 17 and len(payload) >= ihl + 8:
                udp_hdr = payload[ihl:ihl + 8]
                src_port, dst_port, udp_len = struct.unpack(">HHH", udp_hdr[:6])
                app_payload = payload[ihl + 8:ihl + udp_len]

                flow_data["proto"] = "UDP"
                flow_data["src_port"] = src_port
                flow_data["dst_port"] = dst_port

                with self._lock:
                    self.stats["protocols_detected"]["UDP"] = self.stats["protocols_detected"].get("UDP", 0) + 1

                # Deep Packet Inspection
                dpi_res = DpiParser.parse_payload(app_payload, src_port, dst_port, "UDP")
                if dpi_res:
                    flow_data["telemetry"] = dpi_res
                    self._dispatch_telemetry(src_ip, src_mac, dst_ip, vlan_id, dpi_res)

        # Record into TrafficMatrixTracker (Every flow including public WAN endpoints is tracked here)
        if flow_data.get("src_ip") and flow_data.get("dst_ip"):
            try:
                from ui.routes import traffic_matrix_instance
                src_ip = flow_data["src_ip"]
                dst_ip = flow_data["dst_ip"]
                port = flow_data.get("dst_port") or flow_data.get("src_port") or 0
                proto = flow_data.get("proto", "IP")
                telemetry = flow_data.get("telemetry", {})
                app_proto = telemetry.get("protocol", "")
                domain = telemetry.get("sni_hostname", "") or telemetry.get("http_host", "")
                hostname = telemetry.get("hostname", "")
                traffic_matrix_instance.record_flow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    port=port,
                    proto=proto,
                    byte_count=len(frame),
                    app_proto=app_proto,
                    domain=domain,
                    hostname=hostname
                )
            except Exception:
                pass

        # 4. Profinet DCP Processing (EtherType 0x8892)
        elif ethertype == 0x8892:
            from discovery.dpi_parser import ProfinetDcpDecoder
            profinet_info = ProfinetDcpDecoder.decode(payload)
            if profinet_info:
                flow_data["telemetry"] = profinet_info
                flow_data["proto"] = "PROFINET"
                self._dispatch_telemetry(profinet_info.get("ip") or "", src_mac, "", vlan_id, profinet_info)

        # 5. Spanning Tree BPDU Processing (Multicast 01:80:C2:00:00:00 or LLC 0x424203)
        elif dst_mac.startswith("01:80:C2:00:00:00") or (len(payload) >= 3 and payload[:3] == b"\x42\x42\x03"):
            from discovery.dpi_parser import StpBpduDecoder
            stp_info = StpBpduDecoder.decode(payload)
            if stp_info:
                flow_data["telemetry"] = stp_info
                flow_data["proto"] = "STP"
                self._dispatch_telemetry("", src_mac, "", vlan_id, stp_info)

        return flow_data

    def _dispatch_telemetry(self, src_ip: str, src_mac: str, dst_ip: str, vlan_id: Optional[int], dpi: Dict[str, Any]):
        """Transmits discovered host telemetry extracted from DPI streams to callback."""
        if not self.on_node_discovered:
            return

        node_update: Dict[str, Any] = {
            "vlan_id": vlan_id,
            "discovery_method": "mirrored_span_dpi"
        }

        # DHCP Telemetry
        if dpi.get("protocol") == "DHCP":
            target_ip = dpi.get("requested_ip") or src_ip
            target_mac = dpi.get("mac") or src_mac
            if _is_private_ip(target_ip):
                node_update["ip"] = target_ip
                node_update["mac"] = target_mac
                node_update["discovery_method"] = "mirrored_span_dhcp"
                if dpi.get("hostname"):
                    node_update["hostname"] = dpi["hostname"]
                if dpi.get("vendor_class"):
                    node_update["vendor_class"] = dpi["vendor_class"]
                if dpi.get("option55_fingerprint"):
                    node_update["dhcp_option55"] = dpi["option55_fingerprint"]
                self.on_node_discovered(node_update)

        # DNS Response Telemetry (CRITICAL: Only internal private IP records are registered as topology nodes)
        elif dpi.get("protocol") == "DNS" and dpi.get("is_response"):
            for ans in dpi.get("answers", []):
                if ans.get("type") == "A" and ans.get("ip"):
                    ans_ip = ans["ip"]
                    if _is_private_ip(ans_ip):
                        self.on_node_discovered({
                            "ip": ans_ip,
                            "hostname": ans.get("name", ""),
                            "vlan_id": vlan_id,
                            "discovery_method": "mirrored_span_dns"
                        })

        # Ubiquiti UBNT Telemetry
        elif dpi.get("protocol") == "UBNT":
            target_ip = src_ip if _is_private_ip(src_ip) else (dst_ip if _is_private_ip(dst_ip) else "")
            if target_ip or (dpi.get("mac") or src_mac):
                self.on_node_discovered({
                    "ip": target_ip,
                    "mac": dpi.get("mac") or src_mac,
                    "vendor": "Ubiquiti Inc.",
                    "model": dpi.get("model", "Ubiquiti Device"),
                    "type": dpi.get("type", "wlan_ap"),
                    "hostname": dpi.get("hostname", ""),
                    "firmware": dpi.get("firmware", ""),
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_ubnt"
                })

        # MikroTik MNDP Telemetry
        elif dpi.get("protocol") == "MNDP":
            target_ip = src_ip if _is_private_ip(src_ip) else (dst_ip if _is_private_ip(dst_ip) else "")
            if target_ip or (dpi.get("mac") or src_mac):
                self.on_node_discovered({
                    "ip": target_ip,
                    "mac": dpi.get("mac") or src_mac,
                    "vendor": "MikroTik",
                    "model": dpi.get("model", "MikroTik RouterOS"),
                    "type": dpi.get("type", "router"),
                    "hostname": dpi.get("hostname", ""),
                    "firmware": dpi.get("firmware", ""),
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_mndp"
                })

        # Synology & QNAP NAS Telemetry
        elif dpi.get("protocol") in ("SYNOLOGY_ASSISTANT", "QNAP_QFINDER"):
            target_ip = src_ip if _is_private_ip(src_ip) else (dst_ip if _is_private_ip(dst_ip) else "")
            if target_ip or src_mac:
                self.on_node_discovered({
                    "ip": target_ip,
                    "mac": src_mac,
                    "vendor": dpi.get("vendor", "Synology"),
                    "model": dpi.get("model", "NAS Storage Device"),
                    "type": "nas",
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_nas"
                })

        # Profinet DCP Industrial Telemetry
        elif dpi.get("protocol") == "PROFINET_DCP":
            target_ip = dpi.get("ip") or src_ip
            if not target_ip or _is_private_ip(target_ip):
                self.on_node_discovered({
                    "ip": target_ip,
                    "mac": src_mac,
                    "vendor": dpi.get("vendor", "Siemens"),
                    "model": dpi.get("model", "Siemens SIMATIC S7 / Profinet Device"),
                    "type": "plc",
                    "hostname": dpi.get("hostname", ""),
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_profinet"
                })

        # EtherNet/IP CIP Industrial Telemetry
        elif dpi.get("protocol") == "ETHERNET_IP_CIP":
            if _is_private_ip(src_ip):
                self.on_node_discovered({
                    "ip": src_ip,
                    "mac": src_mac,
                    "vendor": dpi.get("vendor", "Rockwell Automation / Allen-Bradley"),
                    "model": dpi.get("model", "Allen-Bradley PLC"),
                    "type": "plc",
                    "firmware": dpi.get("firmware", ""),
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_cip"
                })

        # BACnet/IP Building Automation Telemetry
        elif dpi.get("protocol") == "BACNET_IP":
            # Only register as IoT BACnet controller if verified as an I-Am/I-Have/ACK device response (never Who-Is probe)
            if dpi.get("is_controller") or dpi.get("service") in ("I-Am", "I-Have", "ACK"):
                if _is_private_ip(src_ip):
                    self.on_node_discovered({
                        "ip": src_ip,
                        "mac": src_mac,
                        "vendor": dpi.get("vendor", "BACnet Building Automation"),
                        "model": dpi.get("model", "BACnet Controller"),
                        "type": "iot",
                        "vlan_id": vlan_id,
                        "discovery_method": "mirrored_span_bacnet"
                    })

        # STP BPDU Switch Infrastructure Telemetry
        elif dpi.get("protocol") == "STP_BPDU":
            bridge_mac = dpi.get("bridge_mac") or src_mac
            self.on_node_discovered({
                "ip": "",
                "mac": bridge_mac,
                "type": "switch",
                "vendor": "Enterprise Switch",
                "model": f"Switch ({dpi.get('stp_version', 'STP')})",
                "vlan_id": vlan_id,
                "discovery_method": "mirrored_span_stp_bpdu"
            })

        # TLS SNI Telemetry (Only for private internal IP endpoints)
        elif dpi.get("protocol") == "TLS" and dpi.get("sni_hostname"):
            if _is_private_ip(dst_ip):
                self.on_node_discovered({
                    "ip": dst_ip,
                    "hostname": dpi["sni_hostname"],
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_tls_sni"
                })

        # HTTP Host Telemetry (Only for private internal IP endpoints)
        elif dpi.get("protocol") == "HTTP" and dpi.get("http_host"):
            if _is_private_ip(dst_ip):
                self.on_node_discovered({
                    "ip": dst_ip,
                    "hostname": dpi["http_host"],
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_http"
                })

        # SIP Telemetry
        elif dpi.get("protocol") == "SIP" and dpi.get("sip_user_agent"):
            if _is_private_ip(src_ip):
                self.on_node_discovered({
                    "ip": src_ip,
                    "mac": src_mac,
                    "sip_user_agent": dpi["sip_user_agent"],
                    "type": "voip_phone" if "phone" in dpi["sip_user_agent"].lower() or "gxp" in dpi["sip_user_agent"].lower() else "voip_pbx",
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_sip"
                })

    def start_capture(self, interface: Optional[str] = None):
        """Starts background promiscuous / SPAN packet capture loop."""
        if self._running:
            return
        self.interface = interface or self.interface
        self._running = True

        def _capture_loop():
            # 1. Try Scapy / Npcap if available
            try:
                from scapy.all import sniff
                def _scapy_cb(pkt):
                    if not self._running:
                        return
                    try:
                        self.process_raw_frame(bytes(pkt))
                    except Exception:
                        pass
                
                sniff(iface=self.interface, prn=_scapy_cb, store=False, stop_filter=lambda p: not self._running)
                return
            except Exception:
                pass

            # 2. Fallback to Windows SIO_RCVALL raw socket
            try:
                import socket
                from core.device_classifier import LocationEngine
                loc = LocationEngine.get_local_location()
                local_ip = loc.get("local_ip", "0.0.0.0")

                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((local_ip, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                if hasattr(socket, "SIO_RCVALL") and hasattr(socket, "RCVALL_ON"):
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                s.settimeout(0.5)

                while self._running:
                    try:
                        data, _ = s.recvfrom(65535)
                        dummy_eth = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00" + data
                        self.process_raw_frame(dummy_eth)
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                try:
                    if hasattr(socket, "SIO_RCVALL") and hasattr(socket, "RCVALL_OFF"):
                        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    s.close()
                except Exception:
                    pass
            except Exception:
                pass

        self._thread = threading.Thread(target=_capture_loop, daemon=True)
        self._thread.start()

    def stop_capture(self):
        """Stops live capture loop."""
        self._running = False

    def get_summary_stats(self) -> Dict[str, Any]:
        """Returns snapshot of current mirrored traffic statistics."""
        with self._lock:
            return {
                "packets_captured": self.stats["packets_captured"],
                "bytes_captured": self.stats["bytes_captured"],
                "vlans_discovered": sorted(list(self.stats["vlans_discovered"])),
                "protocols_detected": dict(self.stats["protocols_detected"]),
                "active_hosts_count": len(self.stats["active_hosts"])
            }

