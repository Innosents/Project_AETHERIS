"""
Project AETHERIS - Fast Deep Packet Inspection (DPI) & Protocol Stream Decoder
Parses unencrypted protocol headers and handshake metadata from mirrored SPAN / ERSPAN packet streams.
Supports:
 - DHCP Discover/Request/Ack (Option 12 Hostname, Option 60 Vendor Class, Option 55 Fingerprint)
 - DNS Queries & Responses (A, AAAA, PTR, Active Directory SRV records)
 - TLS Client Hello Server Name Indication (SNI - Extension 0x0000)
 - HTTP/1.1 (Host, User-Agent, Server Headers)
 - SIP VoIP Registrations & RTSP Video Streaming
 - Industrial Protocols (Modbus/TCP, EtherNet/IP, S7comm)
"""

import struct
import re
from typing import Dict, Any, List, Optional, Tuple

from loguru import logger

from aetheris.core.ports.dpi_parser_port import (
    DpiParserPort,
    DpiDecodedPayload,
    DpiPeripheralSubsystem,
    _MappingCompatibleModel,
)

class DhcpDecoder:
    """Decodes DHCP/BOOTP (UDP Ports 67/68) broadcast traffic for device fingerprinting."""

    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses BOOTP/DHCP message options.
        Magic cookie: 0x63825363 at offset 236.
        """
        if len(payload) < 240:
            return None

        # Check BOOTP op: 1 = BOOTREQUEST (Client to Server), 2 = BOOTREPLY (Server to Client)
        op = payload[0]
        chaddr_raw = payload[28:44]
        # Extract client MAC address
        hlen = min(payload[2], 6)
        mac = ":".join(f"{b:02X}" for b in chaddr_raw[:hlen]) if hlen == 6 else ""

        # Check DHCP Magic Cookie
        magic = payload[236:240]
        if magic != b"\x63\x82\x53\x63":
            return None

        results: Dict[str, Any] = {
            "protocol": "DHCP",
            "op": "BOOTREQUEST" if op == 1 else "BOOTREPLY",
            "mac": mac,
            "options": {}
        }

        # Parse DHCP Options TLV (Type-Length-Value)
        pos = 240
        options_len = len(payload)
        opt55_list: List[int] = []

        while pos < options_len:
            opt_type = payload[pos]
            if opt_type == 255:  # End Option
                break
            if opt_type == 0:    # Pad Option
                pos += 1
                continue

            if pos + 1 >= options_len:
                break
            opt_len = payload[pos + 1]
            pos += 2

            if pos + opt_len > options_len:
                break
            opt_val = payload[pos:pos + opt_len]
            pos += opt_len

            if opt_type == 53 and len(opt_val) >= 1:  # DHCP Message Type
                msg_types = {
                    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
                    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"
                }
                results["message_type"] = msg_types.get(opt_val[0], f"TYPE_{opt_val[0]}")
            elif opt_type == 12:  # Hostname
                results["hostname"] = opt_val.decode("utf-8", errors="ignore").strip()
            elif opt_type == 50 and len(opt_val) == 4:  # Requested IP
                results["requested_ip"] = ".".join(str(b) for b in opt_val)
            elif opt_type == 60:  # Vendor Class Identifier (VCI)
                results["vendor_class"] = opt_val.decode("utf-8", errors="ignore").strip()
            elif opt_type == 55:  # Parameter Request List (Option 55 Fingerprint)
                opt55_list = list(opt_val)
                results["option55_fingerprint"] = ",".join(str(x) for x in opt55_list)
            elif opt_type == 81:  # Client FQDN
                try:
                    results["client_fqdn"] = opt_val[3:].decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass

        return results


class DnsDecoder:
    """Decodes DNS (UDP/TCP Port 53) queries and responses to map IP addresses to domains and AD roles."""

    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 12:
            return None

        try:
            tx_id, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", payload[:12])
            is_response = bool(flags & 0x8000)

            results: Dict[str, Any] = {
                "protocol": "DNS",
                "tx_id": tx_id,
                "is_response": is_response,
                "queries": [],
                "answers": []
            }

            pos = 12

            def parse_name(offset: int) -> Tuple[str, int]:
                labels = []
                jumped = False
                orig_offset = offset
                while offset < len(payload):
                    length = payload[offset]
                    if length == 0:
                        offset += 1
                        break
                    elif (length & 0xC0) == 0xC0:
                        # Pointer
                        if offset + 1 >= len(payload):
                            break
                        pointer = ((length & 0x3F) << 8) | payload[offset + 1]
                        if not jumped:
                            orig_offset = offset + 2
                            jumped = True
                        offset = pointer
                    else:
                        offset += 1
                        labels.append(payload[offset:offset + length].decode("utf-8", errors="ignore"))
                        offset += length
                return ".".join(labels), (orig_offset if jumped else offset)

            # Parse Queries
            for _ in range(qdcount):
                if pos >= len(payload):
                    break
                qname, pos = parse_name(pos)
                if pos + 4 <= len(payload):
                    qtype, _ = struct.unpack(">HH", payload[pos:pos + 4])
                    pos += 4
                    type_str = {1: "A", 28: "AAAA", 12: "PTR", 33: "SRV", 15: "MX", 16: "TXT"}.get(qtype, f"TYPE_{qtype}")
                    results["queries"].append({"name": qname, "type": type_str})

            # Parse Answers if response
            if is_response and ancount > 0:
                for _ in range(ancount):
                    if pos >= len(payload):
                        break
                    aname, pos = parse_name(pos)
                    if pos + 10 <= len(payload):
                        atype, _, _, rdlength = struct.unpack(">HHIH", payload[pos:pos + 10])
                        pos += 10
                        rdata_pos = pos
                        pos += rdlength

                        if atype == 1 and rdlength == 4:  # A record (IPv4)
                            ip = ".".join(str(b) for b in payload[rdata_pos:rdata_pos + 4])
                            results["answers"].append({"name": aname, "type": "A", "ip": ip})
                        elif atype == 12:  # PTR record
                            ptr_target, _ = parse_name(rdata_pos)
                            results["answers"].append({"name": aname, "type": "PTR", "target": ptr_target})
                        elif atype == 33 and rdlength >= 6:  # SRV record
                            target_host, _ = parse_name(rdata_pos + 6)
                            results["answers"].append({"name": aname, "type": "SRV", "target": target_host})

            return results
        except Exception:
            return None


class TlsSniDecoder:
    """Decodes TLS Client Hello (Port 443 / 8443) to extract Server Name Indication (SNI) hostnames."""

    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        # TLS Record: ContentType (1 byte = 22 for Handshake), Version (2 bytes), Length (2 bytes)
        if len(payload) < 43 or payload[0] != 22:
            return None

        try:
            # Handshake Header: HandshakeType (1 = Client Hello), Length (3 bytes)
            if payload[5] != 1:
                return None

            pos = 5 + 4  # Skip handshake type and length
            pos += 2     # Skip client version
            pos += 32    # Skip client random

            if pos >= len(payload):
                return None
            session_id_len = payload[pos]
            pos += 1 + session_id_len

            if pos + 2 > len(payload):
                return None
            cipher_suites_len = struct.unpack(">H", payload[pos:pos + 2])[0]
            pos += 2 + cipher_suites_len

            if pos + 1 > len(payload):
                return None
            compression_methods_len = payload[pos]
            pos += 1 + compression_methods_len

            if pos + 2 > len(payload):
                return None
            extensions_len = struct.unpack(">H", payload[pos:pos + 2])[0]
            pos += 2

            end_ext = min(pos + extensions_len, len(payload))
            while pos + 4 <= end_ext:
                ext_type, ext_len = struct.unpack(">HH", payload[pos:pos + 4])
                pos += 4
                if ext_type == 0:  # Extension 0: Server Name Indication (SNI)
                    if pos + 2 <= len(payload):
                        _ = struct.unpack(">H", payload[pos:pos + 2])[0]
                        server_name_type = payload[pos + 2]
                        if server_name_type == 0:  # Host Name
                            name_len = struct.unpack(">H", payload[pos + 3:pos + 5])[0]
                            sni_bytes = payload[pos + 5:pos + 5 + name_len]
                            sni_hostname = sni_bytes.decode("utf-8", errors="ignore").strip()
                            return {
                                "protocol": "TLS",
                                "sni_hostname": sni_hostname
                            }
                pos += ext_len
        except Exception:
            pass

        return None


class HttpDecoder:
    """Decodes plain HTTP/1.1 headers (Ports 80, 8080, 8000, etc.) for hostnames, user agents, and servers."""

    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 14:
            return None

        try:
            text = payload[:2048].decode("latin-1", errors="ignore")
            # Match HTTP methods or responses
            if re.match(r'^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|TRACE|HTTP/1\.)', text):
                results: Dict[str, Any] = {"protocol": "HTTP"}

                host_m = re.search(r'Host:\s*([^\r\n:]+)', text, re.IGNORECASE)
                if host_m:
                    results["http_host"] = host_m.group(1).strip()

                ua_m = re.search(r'User-Agent:\s*([^\r\n]+)', text, re.IGNORECASE)
                if ua_m:
                    results["user_agent"] = ua_m.group(1).strip()

                server_m = re.search(r'Server:\s*([^\r\n]+)', text, re.IGNORECASE)
                if server_m:
                    results["http_server"] = server_m.group(1).strip()

                return results
        except Exception:
            pass

        return None


class VoipOtDecoder:
    """Decodes SIP Telephony and Industrial Protocol packets (Modbus, EtherNet/IP, S7)."""

    @staticmethod
    def decode(payload: bytes, dst_port: int) -> Optional[Dict[str, Any]]:
        if len(payload) < 8:
            return None

        # 1. SIP Telephony (UDP/TCP 5060/5061)
        if dst_port in (5060, 5061) or b"SIP/2.0" in payload[:50]:
            try:
                text = payload[:1024].decode("latin-1", errors="ignore")
                if "SIP/2.0" in text:
                    results = {"protocol": "SIP"}
                    ua_m = re.search(r'(?:User-Agent|Server):\s*([^\r\n]+)', text, re.IGNORECASE)
                    if ua_m:
                        results["sip_user_agent"] = ua_m.group(1).strip()
                    from_m = re.search(r'From:\s*<sip:([^@>]+)@([^>]+)>', text, re.IGNORECASE)
                    if from_m:
                        results["sip_extension"] = from_m.group(1)
                        results["sip_domain"] = from_m.group(2)
                    return results
            except Exception:
                pass

        # 2. Modbus/TCP (Port 502)
        if dst_port == 502 and len(payload) >= 8:
            # Modbus MBAP Header: TxID (2B), ProtoID (2B == 0), Length (2B), UnitID (1B), FunctionCode (1B)
            proto_id = struct.unpack(">H", payload[2:4])[0]
            if proto_id == 0:
                unit_id = payload[6]
                func_code = payload[7]
                return {
                    "protocol": "MODBUS",
                    "unit_id": unit_id,
                    "function_code": func_code
                }

        # 3. S7comm (Port 102 - TPKT + COTP + S7)
        if dst_port == 102 and len(payload) >= 10 and payload[0] == 3 and payload[1] == 0:
            return {
                "protocol": "S7COMM",
                "tpkt_length": struct.unpack(">H", payload[2:4])[0]
            }

        return None


class UbntDiscoveryDecoder:
    """Decodes Ubiquiti Discovery Protocol (UBNT - UDP 10001) packets."""
    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 4:
            return None
        if payload[0] not in (1, 2):
            return None
        
        results = {
            "protocol": "UBNT",
            "vendor": "Ubiquiti Inc.",
            "type": "wlan_ap",
            "model": "Ubiquiti Device",
            "hostname": "",
            "firmware": "",
            "mac": ""
        }
        
        pos = 4
        while pos + 3 <= len(payload):
            tlv_type = payload[pos]
            tlv_len = struct.unpack(">H", payload[pos+1:pos+3])[0]
            pos += 3
            if pos + tlv_len > len(payload):
                break
            val = payload[pos:pos+tlv_len]
            pos += tlv_len
            
            if tlv_type == 0x01 and tlv_len == 6:
                results["mac"] = ":".join(f"{b:02X}" for b in val)
            elif tlv_type == 0x03:
                results["firmware"] = val.decode("utf-8", errors="ignore").strip()
            elif tlv_type == 0x0B:
                results["hostname"] = val.decode("utf-8", errors="ignore").strip()
            elif tlv_type in (0x0C, 0x14, 0x15):
                model_str = val.decode("utf-8", errors="ignore").strip()
                if model_str:
                    results["model"] = f"Ubiquiti {model_str}"
                    if any(x in model_str.lower() for x in ("switch", "usw", "edgeswitch")):
                        results["type"] = "switch"
                    elif any(x in model_str.lower() for x in ("udm", "edgerouter", "gateway", "uxg")):
                        results["type"] = "router"
                    elif any(x in model_str.lower() for x in ("u6", "u7", "ap", "unifi", "airmax", "nanostation")):
                        results["type"] = "wlan_ap"
        return results if results.get("mac") or results.get("hostname") or results.get("firmware") else None


class MikrotikMndpDecoder:
    """Decodes MikroTik Neighbor Discovery Protocol (MNDP - UDP 5678) packets."""
    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 4:
            return None
        
        results = {
            "protocol": "MNDP",
            "vendor": "MikroTik",
            "type": "router",
            "model": "MikroTik RouterOS Device",
            "hostname": "",
            "firmware": "",
            "mac": ""
        }
        
        pos = 0
        while pos + 4 <= len(payload):
            tlv_type, tlv_len = struct.unpack(">HH", payload[pos:pos+4])
            pos += 4
            if pos + tlv_len > len(payload):
                break
            val = payload[pos:pos+tlv_len]
            pos += tlv_len
            
            if tlv_type == 0x01 and tlv_len == 6:
                results["mac"] = ":".join(f"{b:02X}" for b in val)
            elif tlv_type == 0x05:
                results["hostname"] = val.decode("utf-8", errors="ignore").strip()
            elif tlv_type == 0x07:
                results["firmware"] = f"RouterOS {val.decode('utf-8', errors='ignore').strip()}"
            elif tlv_type == 0x08:
                board = val.decode("utf-8", errors="ignore").strip()
                results["model"] = f"MikroTik {board}"
                if "crs" in board.lower() or "switch" in board.lower():
                    results["type"] = "switch"
            elif tlv_type == 0x0A:
                results["architecture"] = val.decode("utf-8", errors="ignore").strip()
                
        return results if results.get("mac") or results.get("hostname") or results.get("firmware") else None


class SynologyQnapDecoder:
    """Decodes Synology Assistant (UDP 9999) & QNAP Qfinder (UDP 8097) NAS broadcasts."""
    @staticmethod
    def decode(payload: bytes, port: int) -> Optional[Dict[str, Any]]:
        if len(payload) < 8:
            return None
            
        text = payload.decode("latin1", errors="ignore")
        lowered = text.lower()
        
        if "synology" in lowered or "diskstation" in lowered or port == 9999:
            results = {
                "protocol": "SYNOLOGY_ASSISTANT",
                "vendor": "Synology",
                "type": "nas",
                "model": "Synology DiskStation NAS",
                "hostname": "",
                "firmware": ""
            }
            m = re.search(r'(DS\d{3,4}\+?|RS\d{3,4}\+?)', text, re.IGNORECASE)
            if m:
                results["model"] = f"Synology {m.group(1).upper()}"
            return results
            
        elif "qnap" in lowered or port == 8097:
            results = {
                "protocol": "QNAP_QFINDER",
                "vendor": "QNAP Systems",
                "type": "nas",
                "model": "QNAP Turbo NAS",
                "hostname": "",
                "firmware": ""
            }
            m = re.search(r'(TS-\d{3,4}[A-Za-z\+]*)', text, re.IGNORECASE)
            if m:
                results["model"] = f"QNAP {m.group(1).upper()}"
            return results
            
        return None


class StpBpduDecoder:
    """Decodes 802.1D / 802.1w Spanning Tree Protocol (STP / RSTP / MSTP) BPDUs."""
    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) >= 3 and payload[:3] == b"\x42\x42\x03":
            payload = payload[3:]
            
        if len(payload) < 35:
            return None
            
        proto_id, version, bpdu_type = struct.unpack(">HBB", payload[:4])
        if proto_id != 0:
            return None
            
        flags = payload[4]
        root_prio = struct.unpack(">H", payload[5:7])[0]
        root_mac = ":".join(f"{b:02X}" for b in payload[7:13])
        root_path_cost = struct.unpack(">I", payload[13:17])[0]
        bridge_prio = struct.unpack(">H", payload[17:19])[0]
        bridge_mac = ":".join(f"{b:02X}" for b in payload[19:25])
        port_id = struct.unpack(">H", payload[25:27])[0]
        
        is_root = (root_mac == bridge_mac)
        stp_ver_map = {0: "STP (802.1D)", 2: "RSTP (802.1w)", 3: "MSTP (802.1s)"}
        
        return {
            "protocol": "STP_BPDU",
            "stp_version": stp_ver_map.get(version, f"STP_v{version}"),
            "bpdu_type": "TopologyChange" if bpdu_type == 0x80 else ("RSTP" if bpdu_type == 0x02 else "Config"),
            "root_bridge_mac": root_mac,
            "root_priority": root_prio,
            "root_path_cost": root_path_cost,
            "bridge_mac": bridge_mac,
            "bridge_priority": bridge_prio,
            "port_id": port_id,
            "is_root_bridge": is_root,
            "tc_flag": bool(flags & 0x01)
        }


class ProfinetDcpDecoder:
    """Decodes Profinet DCP (Discovery and Configuration Protocol - EtherType 0x8892) frames."""
    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 10:
            return None
            
        service_id, service_type = payload[0], payload[1]
        xid = struct.unpack(">I", payload[2:6])[0]
        resp_delay = struct.unpack(">H", payload[6:8])[0]
        dcp_len = struct.unpack(">H", payload[8:10])[0]
        
        results = {
            "protocol": "PROFINET_DCP",
            "vendor": "Siemens",
            "type": "plc",
            "model": "Siemens SIMATIC S7 / Profinet Device",
            "hostname": "",
            "ip": ""
        }
        
        pos = 10
        end_pos = min(len(payload), 10 + dcp_len) if dcp_len > 0 else len(payload)
        while pos + 4 <= end_pos:
            opt = payload[pos]
            subopt = payload[pos+1]
            block_len = struct.unpack(">H", payload[pos+2:pos+4])[0]
            pos += 4
            if pos + block_len > len(payload):
                break
            block_data = payload[pos:pos+block_len]
            pos += block_len
            
            if opt == 0x02:
                if subopt == 0x01:
                    name_bytes = block_data[2:] if len(block_data) > 2 else block_data
                    results["hostname"] = name_bytes.decode("utf-8", errors="ignore").strip("\x00")
                elif subopt == 0x02 and len(block_data) >= 6:
                    vendor_id = struct.unpack(">H", block_data[2:4])[0]
                    device_id = struct.unpack(">H", block_data[4:6])[0]
                    if vendor_id == 0x002A:
                        results["vendor"] = "Siemens AG"
                        results["model"] = f"Siemens SIMATIC Profinet Node (DeviceID: 0x{device_id:04X})"
            elif opt == 0x01 and subopt == 0x02 and len(block_data) >= 6:
                results["ip"] = ".".join(str(b) for b in block_data[2:6])
                
        return results if results.get("hostname") or results.get("ip") else None


class EthernetIpCipDecoder:
    """Decodes EtherNet/IP CIP List Identity (UDP/TCP 44818) responses."""
    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 24:
            return None
            
        cmd = struct.unpack("<H", payload[:2])[0]
        length = struct.unpack("<H", payload[2:4])[0]
        if cmd != 0x0063:
            return None
            
        pos = 24
        if pos + 2 > len(payload):
            return None
            
        item_count = struct.unpack("<H", payload[pos:pos+2])[0]
        pos += 2
        
        results = {
            "protocol": "ETHERNET_IP_CIP",
            "vendor": "Rockwell Automation / Allen-Bradley",
            "type": "plc",
            "model": "Allen-Bradley ControlLogix / CompactLogix PLC",
            "product_name": "",
            "serial_number": "",
            "firmware": ""
        }
        
        for _ in range(item_count):
            if pos + 4 > len(payload):
                break
            item_type, item_len = struct.unpack("<HH", payload[pos:pos+4])
            pos += 4
            if pos + item_len > len(payload):
                break
            item_data = payload[pos:pos+item_len]
            pos += item_len
            
            if item_type == 0x000C and len(item_data) >= 30:
                vendor_id = struct.unpack("<H", item_data[18:20])[0]
                dev_type_id = struct.unpack("<H", item_data[20:22])[0]
                prod_code = struct.unpack("<H", item_data[22:24])[0]
                major_rev = item_data[24]
                minor_rev = item_data[25]
                results["firmware"] = f"v{major_rev}.{minor_rev}"
                
                if len(item_data) >= 31:
                    str_len = item_data[30]
                    if len(item_data) >= 31 + str_len:
                        prod_name = item_data[31:31+str_len].decode("utf-8", errors="ignore").strip()
                        results["product_name"] = prod_name
                        results["model"] = f"Allen-Bradley {prod_name}"
                        
                if vendor_id == 1:
                    results["vendor"] = "Rockwell Automation / Allen-Bradley"
                if dev_type_id == 0x000E:
                    results["type"] = "plc"
                    
        return results if results.get("product_name") or results.get("firmware") else None


class BacnetIpDecoder:
    """Decodes BACnet/IP (UDP 47808) building automation frames (Who-Is / I-Am / ACKs)."""
    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 6:
            return None
            
        if payload[0] != 0x81:
            return None
        
        npdu_version = payload[4]
        if npdu_version != 0x01:
            return None
            
        npdu_ctrl = payload[5]
        pos = 6
        
        # Handle DNET/DLEN/DADR and Hop Count (bit 5)
        if npdu_ctrl & 0x20:
            if pos + 4 > len(payload):
                return None
            dlen = payload[pos+2]
            pos += 3 + dlen + 1  # 2B DNET + 1B DLEN + dlen DADR + 1B Hop Count
                
        # Handle SNET/SLEN/SADR (bit 3)
        if npdu_ctrl & 0x08:
            if pos + 3 > len(payload):
                return None
            slen = payload[pos+2]
            pos += 3 + slen
            
        if pos >= len(payload):
            return None

        # Network layer message (bit 7)
        if npdu_ctrl & 0x80:
            return {
                "protocol": "BACNET_IP",
                "service": "NetworkLayerMessage",
                "is_controller": False
            }

        apdu_byte = payload[pos]
        apdu_type = (apdu_byte >> 4) & 0x0F
        
        # APDU Type 1: Unconfirmed-Request-PDU (e.g. I-Am, Who-Is, I-Have)
        if apdu_type == 1:
            if pos + 1 < len(payload):
                service_choice = payload[pos+1]
                if service_choice == 0x00:
                    # I-Am announcement from an actual BACnet device / controller
                    results = {
                        "protocol": "BACNET_IP",
                        "vendor": "BACnet Building Automation",
                        "type": "iot",
                        "model": "BACnet Controller / Environmental Sensor",
                        "service": "I-Am",
                        "is_controller": True
                    }
                    try:
                        iam_pos = pos + 2
                        if iam_pos + 5 <= len(payload) and payload[iam_pos] == 0xC4:
                            dev_id = struct.unpack(">I", payload[iam_pos+1:iam_pos+5])[0] & 0x3FFFFF
                            results["device_instance"] = dev_id
                            results["model"] = f"BACnet Device (ID: {dev_id})"
                    except Exception:
                        pass
                    return results
                elif service_choice == 0x08:
                    # Who-Is discovery query from client/management host (NOT a controller)
                    return {
                        "protocol": "BACNET_IP",
                        "service": "Who-Is",
                        "is_controller": False
                    }
                elif service_choice == 0x01:
                    # I-Have announcement
                    return {
                        "protocol": "BACNET_IP",
                        "vendor": "BACnet Building Automation",
                        "type": "iot",
                        "model": "BACnet Controller",
                        "service": "I-Have",
                        "is_controller": True
                    }
        # APDU Type 2 or 3: ACK response from controller
        elif apdu_type in (2, 3):
            return {
                "protocol": "BACNET_IP",
                "vendor": "BACnet Building Automation",
                "type": "iot",
                "model": "BACnet Controller",
                "service": "ACK",
                "is_controller": True
            }
        # APDU Type 0: Confirmed-Request
        elif apdu_type == 0:
            return {
                "protocol": "BACNET_IP",
                "service": "Confirmed-Req",
                "is_controller": False
            }

        return {
            "protocol": "BACNET_IP",
            "service": "generic",
            "is_controller": False
        }


class MercuryMspDecoder:
    """Decodes Mercury Security Protocol (MSP) framing from raw stream captures (TCP port 3001)."""

    @staticmethod
    def decode(payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Decodes raw MSP frame into access controller metadata and peripheral sub-bus entities.
        Guarantees strict bounds and exception safety.
        """
        try:
            if not payload or len(payload) < 4 or payload[0] != 0x02:
                return None

            clean = payload.strip(b"\x02\x03\r\n ")
            if b"READY" not in clean:
                return None

            payload_str = clean.decode(errors="ignore")
            tokens = payload_str.split("_")

            vendor = "Mercury Security"
            model = "Mercury Access Panel"
            firmware = ""

            for token in tokens:
                t_upper = token.upper()
                if "MERCURY" in t_upper:
                    vendor = "Mercury Security"
                elif any(t_upper.startswith(prefix) for prefix in ("MP", "LP", "EP", "MR")):
                    model = f"Mercury {token}"
                elif t_upper.startswith("V") and len(token) > 1 and token[1:].isdigit():
                    firmware = f"v{token[1:]}"

            token_pattern = re.compile(r"^([RXSD])(\d{1,3})$")
            type_map = {
                "R": {"type": "card_reader", "protocol": "SIA OSDP v2.2", "prefix": "reader_sub", "port": "RS-485 Reader Port"},
                "X": {"type": "rex_sensor", "protocol": "Supervised Analog Input", "prefix": "rex_input", "port": "REX Input Point"},
                "S": {"type": "door_strike", "protocol": "Form-C Dry Contact Relay", "prefix": "strike_relay", "port": "Relay Strike Output"},
                "D": {"type": "dps_contact", "protocol": "Supervised Reed Contact", "prefix": "dps_input", "port": "DPS Input Point"}
            }

            peripherals = []
            for token in tokens:
                token = token.strip()
                match = token_pattern.match(token)
                if match:
                    bus_type, count_str = match.groups()
                    count = int(count_str)
                    meta = type_map[bus_type]
                    for idx in range(1, count + 1):
                        peripherals.append({
                            "id": f"{meta['prefix']}_{idx}",
                            "name": f"{meta['type'].replace('_', ' ').title()} {idx}",
                            "type": meta["type"],
                            "protocol": meta["protocol"],
                            "port": f"{meta['port']} {idx}",
                            "status": "Online / Supervised"
                        })

            return {
                "protocol": "MSP",
                "type": "access_control",
                "vendor": vendor,
                "model": model,
                "firmware": firmware,
                "peripherals": peripherals,
                "raw_msp_handshake": payload_str
            }
        except Exception:
            return None


class DpiParser(DpiParserPort):
    """Unified Deep Packet Inspection dispatcher across all supported application protocols."""

    @staticmethod
    def _build_outcome(raw_res: Optional[Dict[str, Any]]) -> DpiDecodedPayload:
        if not raw_res:
            return DpiDecodedPayload(protocol="UNKNOWN", raw_metadata={})

        protocol = raw_res.get("protocol", "UNKNOWN")
        vendor = raw_res.get("vendor")
        model = raw_res.get("model")
        dev_type = raw_res.get("type")
        hostname = raw_res.get("hostname") or raw_res.get("http_host") or raw_res.get("sni_hostname")
        mac = raw_res.get("mac")
        ip = raw_res.get("requested_ip") or raw_res.get("ip")
        firmware = raw_res.get("firmware")
        options = raw_res.get("options") if isinstance(raw_res.get("options"), dict) else {}

        periph_objs: List[DpiPeripheralSubsystem] = []
        if "peripherals" in raw_res and isinstance(raw_res["peripherals"], list):
            for p in raw_res["peripherals"]:
                if isinstance(p, DpiPeripheralSubsystem):
                    periph_objs.append(p)
                elif isinstance(p, dict):
                    periph_objs.append(
                        DpiPeripheralSubsystem(
                            id=p.get("id", ""),
                            name=p.get("name", ""),
                            type=p.get("type", ""),
                            protocol=p.get("protocol", ""),
                            port=p.get("port", ""),
                            status=p.get("status", "Online / Supervised"),
                            edge_type=p.get("edge_type"),
                        )
                    )

        extra_fields = {
            k: v
            for k, v in raw_res.items()
            if k not in (
                "protocol",
                "vendor",
                "model",
                "type",
                "hostname",
                "mac",
                "ip",
                "firmware",
                "options",
                "peripherals",
                "raw_metadata",
            )
        }

        return DpiDecodedPayload(
            protocol=protocol,
            vendor=vendor,
            model=model,
            type=dev_type,
            hostname=hostname,
            mac=mac,
            ip=ip,
            firmware=firmware,
            options=options,
            peripherals=periph_objs,
            raw_metadata=raw_res,
            **extra_fields,
        )

    @staticmethod
    def parse_secure_payload(data: bytes) -> Optional[dict]:
        MIN_REQUIRED_LENGTH = 14
        if not data or len(data) < MIN_REQUIRED_LENGTH:
            logger.debug(
                f"[DPI Guard] Payload dropped: length {len(data) if data else 0} below minimum threshold {MIN_REQUIRED_LENGTH}"
            )
            return None
        try:
            cmd, length = struct.unpack(">HH", data[:4])
            if len(data) < 4 + length:
                return None
        except struct.error as e:
            logger.error(f"[DPI Error] Malformed frame structure: {e}")
            return None
        return {}

    @staticmethod
    def parse_payload(
        payload: bytes, src_port: int, dst_port: int, proto: str
    ) -> DpiDecodedPayload:
        """Inspects application layer payload and extracts protocol-specific discovery telemetry."""
        results: Dict[str, Any] = {}
        if not payload:
            return DpiParser._build_outcome(results)

        # 0. Mercury Security Protocol (TCP 3001)
        if (
            src_port == 3001
            or dst_port == 3001
            or (payload and payload[0] == 0x02 and b"READY" in payload)
        ):
            msp_info = MercuryMspDecoder.decode(payload)
            if msp_info:
                model = msp_info.get("model", "")
                if "MP1502" in model or "LP" in model:
                    try:
                        from aetheris.core.parsers.mercury_parser import MSPParser
                        import asyncio

                        parser = MSPParser("127.0.0.1", 3001)
                    except Exception:
                        pass

                    new_peripherals = []
                    for p in msp_info.get("peripherals", []):
                        p_copy = dict(p)
                        if "Reader" in p_copy.get("name", ""):
                            p_copy["edge_type"] = "composite_22_6"
                        elif "Strike" in p_copy.get("name", ""):
                            p_copy["edge_type"] = "composite_18_2"
                        else:
                            p_copy["edge_type"] = "composite_22_4"
                        new_peripherals.append(p_copy)
                    msp_info["peripherals"] = new_peripherals

                results.update(msp_info)
                return DpiParser._build_outcome(results)

        # 1. DHCP / BOOTP (UDP 67 / 68)
        if proto == "UDP" and (src_port in (67, 68) or dst_port in (67, 68)):
            dhcp_info = DhcpDecoder.decode(payload)
            if dhcp_info:
                results.update(dhcp_info)
                return DpiParser._build_outcome(results)

        # 2. DNS (UDP / TCP 53)
        if src_port == 53 or dst_port == 53:
            dns_info = DnsDecoder.decode(payload)
            if dns_info:
                results.update(dns_info)
                return DpiParser._build_outcome(results)

        # 3. Ubiquiti UBNT Discovery (UDP 10001)
        if src_port == 10001 or dst_port == 10001:
            ubnt_info = UbntDiscoveryDecoder.decode(payload)
            if ubnt_info:
                results.update(ubnt_info)
                return DpiParser._build_outcome(results)

        # 4. MikroTik MNDP (UDP 5678)
        if src_port == 5678 or dst_port == 5678:
            mndp_info = MikrotikMndpDecoder.decode(payload)
            if mndp_info:
                results.update(mndp_info)
                return DpiParser._build_outcome(results)

        # 5. Synology Assistant (UDP 9999) & QNAP Qfinder (UDP 8097)
        if src_port in (9999, 8097) or dst_port in (9999, 8097):
            nas_info = SynologyQnapDecoder.decode(payload, dst_port or src_port)
            if nas_info:
                results.update(nas_info)
                return DpiParser._build_outcome(results)

        # 6. BACnet/IP (UDP 47808)
        if src_port == 47808 or dst_port == 47808:
            bacnet_info = BacnetIpDecoder.decode(payload)
            if bacnet_info:
                results.update(bacnet_info)
                return DpiParser._build_outcome(results)

        # 7. EtherNet/IP CIP (UDP / TCP 44818)
        if src_port == 44818 or dst_port == 44818:
            cip_info = EthernetIpCipDecoder.decode(payload)
            if cip_info:
                results.update(cip_info)
                return DpiParser._build_outcome(results)

        # 8. TLS Client Hello SNI (TCP 443, 8443, etc.)
        if dst_port in (443, 8443, 9443, 10443) or (payload and payload[0] == 22):
            tls_info = TlsSniDecoder.decode(payload)
            if tls_info:
                results.update(tls_info)
                return DpiParser._build_outcome(results)

        # 9. HTTP / Web (TCP 80, 8080, 8000, etc.)
        if dst_port in (80, 8080, 8000, 8088, 8888, 5000, 3000) or src_port in (
            80,
            8080,
            8000,
        ):
            http_info = HttpDecoder.decode(payload)
            if http_info:
                results.update(http_info)
                return DpiParser._build_outcome(results)

        # 10. VoIP & Industrial Protocols (SIP, Modbus, S7)
        voip_ot = VoipOtDecoder.decode(payload, dst_port)
        if voip_ot:
            results.update(voip_ot)
            return DpiParser._build_outcome(results)

        return DpiParser._build_outcome(results)


__all__ = [
    "DpiParser",
    "DpiParserPort",
    "DpiDecodedPayload",
    "DpiPeripheralSubsystem",
    "_MappingCompatibleModel",
    "DhcpDecoder",
    "DnsDecoder",
    "TlsSniDecoder",
    "HttpDecoder",
    "VoipOtDecoder",
    "UbntDiscoveryDecoder",
    "MikrotikMndpDecoder",
    "SynologyQnapDecoder",
    "StpBpduDecoder",
    "ProfinetDcpDecoder",
    "EthernetIpCipDecoder",
    "BacnetIpDecoder",
    "MercuryMspDecoder",
]

