"""
Project AETHERIS - Port Mirroring (SPAN/RSPAN/ERSPAN) & Frame Ingestion Engine
Handles:
 - Promiscuous Network Interface packet capture & Ring Buffering
 - 802.1Q & 802.1ad (QinQ) Multi-VLAN Tag Extraction
 - ERSPAN Type II / III (GRE IP Proto 47) Decapsulation
 - L2/L3/L4 Protocol Demuxing and DPI Stream Hand-off
"""

import collections
import socket
import struct
import threading
import time
import ipaddress
from typing import Dict, Any, List, Optional, Tuple, Callable, Set, Union
from aetheris.core.ports.mirror_engine_port import (
    MirrorEnginePort,
    DissectedFlowRecord,
    MirrorCaptureSummary,
    _MappingCompatibleModel,
)
from aetheris.discovery.dpi_parser import DpiParser
from aetheris.discovery.advanced_spatial_prober import AdvancedSpatialProber


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


class _ThreadStatsBucket:
    """Thread-isolated statistics accumulator eliminating cross-thread mutex contention."""
    def __init__(self):
        self.packets_captured: int = 0
        self.bytes_captured: int = 0
        self.vlans_discovered: Set[int] = set()
        self.protocols_detected: Dict[str, int] = collections.defaultdict(int)
        self.active_hosts: Set[str] = set()


class ZeroLockStatsProxy:
    """
    Thread-isolated zero-lock statistics container.
    Worker ingestion threads record metrics into thread-local buckets with zero mutex contention.
    Reads dynamically aggregate snapshots across all active thread buckets.
    """
    def __init__(self):
        self._thread_buckets: List[_ThreadStatsBucket] = []
        self._bucket_lock = threading.Lock()

    def register_bucket(self, bucket: _ThreadStatsBucket) -> None:
        with self._bucket_lock:
            self._thread_buckets.append(bucket)

    def snapshot(self) -> Dict[str, Any]:
        with self._bucket_lock:
            buckets = list(self._thread_buckets)

        total_pkts = sum(b.packets_captured for b in buckets)
        total_bytes = sum(b.bytes_captured for b in buckets)
        vlans: Set[int] = set()
        for b in buckets:
            vlans.update(b.vlans_discovered)
        hosts: Set[str] = set()
        for b in buckets:
            hosts.update(b.active_hosts)
        protos: Dict[str, int] = collections.defaultdict(int)
        for b in buckets:
            for p, count in b.protocols_detected.items():
                protos[p] += count

        return {
            "packets_captured": total_pkts,
            "bytes_captured": total_bytes,
            "vlans_discovered": vlans,
            "protocols_detected": dict(protos),
            "active_hosts": hosts,
        }

    def __getitem__(self, key: str) -> Any:
        return self.snapshot()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.snapshot().get(key, default)


class BoundedFlowWindowRing:
    """
    O(1) LRU bounded time-series ledger for microsecond packet arrival dispersion.
    Guarantees thread-local zero-lock isolation and strictly bounded heap footprint.
    """
    def __init__(self, max_flows: int = 1024, max_window: int = 32):
        self.max_flows = max_flows
        self.max_window = max_window
        self._flows: collections.OrderedDict[Tuple[str, str, int, int], collections.deque] = collections.OrderedDict()

    def get_or_create(self, key: Tuple[str, str, int, int]) -> collections.deque:
        if key in self._flows:
            self._flows.move_to_end(key)
            return self._flows[key]
        if len(self._flows) >= self.max_flows:
            self._flows.popitem(last=False)  # O(1) LRU temporal eviction
        buf = collections.deque(maxlen=self.max_window)
        self._flows[key] = buf
        return buf


class OtWireDissector:
    """Dissects industrial OT/ICS protocol payloads directly from wire frames."""

    @staticmethod
    def dissect_modbus_tcp(payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Dissects Modbus TCP MBAP Header (7 bytes) + PDU:
        [Transaction ID: 2B][Protocol ID: 2B (0x0000)][Length: 2B][Unit ID: 1B][Function Code: 1B][Data: N-B]
        """
        if len(payload) < 8:
            return None
        tx_id, proto_id, length, unit_id, func_code = struct.unpack(">HHHBB", payload[:8])
        if proto_id != 0:
            return None  # RFC compliant Modbus protocol identifier must be 0

        pdu = payload[8:6 + length] if len(payload) >= 6 + length else payload[8:]
        info: Dict[str, Any] = {
            "protocol": "MODBUS",
            "transaction_id": tx_id,
            "unit_id": unit_id,
            "function_code": func_code,
            "is_exception": bool(func_code & 0x80),
        }
        if func_code in (1, 2, 3, 4) and len(pdu) >= 4:
            info["reference_address"], info["word_count"] = struct.unpack(">HH", pdu[:4])
        elif func_code in (5, 6) and len(pdu) >= 4:
            info["reference_address"], info["register_value"] = struct.unpack(">HH", pdu[:4])
        elif func_code == 0x2B and len(pdu) >= 2:
            info["mei_type"] = pdu[0]
            info["device_id_read"] = True
        return info

    @staticmethod
    def dissect_bacnet_ip(payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Dissects BACnet Virtual Link Control (BVLC) + NPDU + APDU:
        [BVLC Type: 0x81 (1B)][Function: 1B][Length: 2B]
        """
        if len(payload) < 4 or payload[0] != 0x81:
            return None
        bvlc_type, bvlc_func, bvlc_len = struct.unpack(">BBH", payload[:4])
        if len(payload) < bvlc_len or bvlc_len < 6:
            return None

        npdu_pos = 4
        if npdu_pos >= len(payload) or payload[npdu_pos] != 0x01:  # BACnet protocol version 1
            return None
        npdu_pos += 1
        npdu_ctrl = payload[npdu_pos]
        npdu_pos += 1

        pos = npdu_pos
        if npdu_ctrl & 0x20:  # Destination specifier present
            if pos + 3 <= len(payload):
                dnet, dlen = struct.unpack(">HB", payload[pos:pos + 3])
                pos += 3 + dlen + 1
        if npdu_ctrl & 0x08:  # Source specifier present
            if pos + 3 <= len(payload):
                snet, slen = struct.unpack(">HB", payload[pos:pos + 3])
                pos += 3 + slen

        apdu = payload[pos:bvlc_len]
        if not apdu:
            return None

        apdu_type = (apdu[0] >> 4) & 0x0F
        service_choice = apdu[1] if len(apdu) > 1 else None

        service_map = {
            0: "I-Am",
            1: "I-Have",
            8: "Who-Is",
            12: "ReadProperty",
            14: "ReadPropertyMultiple",
            15: "WriteProperty",
        }
        service_name = service_map.get(service_choice, f"Service_{service_choice}") if service_choice is not None else "Unknown"

        return {
            "protocol": "BACNET_IP",
            "bvlc_function": bvlc_func,
            "apdu_type": apdu_type,
            "service_choice": service_choice,
            "service": service_name,
            "is_controller": bool(apdu_type in (0, 1, 2, 3) or service_choice in (0, 1, 12, 14, 15)),
            "raw_apdu_len": len(apdu),
        }

    @staticmethod
    def dissect_mercury_msp(payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Dissects Mercury Security Protocol (MSP) framing over TCP Port 3001:
        Format: STX (0x02) ... ETX (0x03) or binary command envelope.
        """
        if len(payload) < 4:
            return None
        if payload[0] == 0x02:
            etx_idx = payload.find(b"\x03")
            body = payload[1:etx_idx] if etx_idx != -1 else payload[1:]
            decoded_body = body.decode(errors="ignore")
            model = "Mercury Security Controller"
            for m in ("MP1502", "LP4502", "EP1502", "LP1502", "MR52", "MR50"):
                if m in decoded_body.upper():
                    model = f"Mercury {m}"
                    break
            return {
                "protocol": "MERCURY_MSP",
                "framing": "STX_ETX",
                "body": decoded_body,
                "model": model,
                "is_ready": "READY" in decoded_body.upper(),
                "length": len(body),
            }
        if len(payload) >= 6 and payload[:2] == b"\xFF\xFE":
            panel_id, cmd_code = struct.unpack(">HB", payload[2:5])
            return {
                "protocol": "MERCURY_MSP",
                "framing": "BINARY",
                "panel_id": panel_id,
                "command_code": cmd_code,
                "model": "Mercury Controller (Binary Mode)",
                "length": len(payload),
            }
        return None


class SpanCaptureEngine(MirrorEnginePort):
    """
    Ingests mirrored SPAN / ERSPAN / TAP packets, extracts L2/L3/L4 headers,
    runs Deep Packet Inspection (DPI), and updates node discovery and traffic flows.
    """

    def __init__(self, interface: str = None, on_node_discovered: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.interface = interface
        self.on_node_discovered = on_node_discovered
        self._running = False
        self._lock = threading.Lock()
        # Lock-Free Ring Buffer: thread-local sliding windows to guarantee zero lock contention
        self._thread_local = threading.local()
        self._stats_proxy = ZeroLockStatsProxy()
        self.stats = self._stats_proxy
        self.ptp_capability = AdvancedSpatialProber.evaluate_ptp_hardware_timestamp_viability(
            interface)

    def _get_thread_stats(self) -> _ThreadStatsBucket:
        if not hasattr(self._thread_local, 'stats_bucket'):
            bucket = _ThreadStatsBucket()
            self._thread_local.stats_bucket = bucket
            self._stats_proxy.register_bucket(bucket)
        return self._thread_local.stats_bucket

    def _evaluate_span_jitter(
        self,
        flow_key: Tuple[str, str, int, int],
        timestamps: Dict[str, Any],
        arrival_ns: int,
        os_profile: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Ingests RFC 7323 timestamp sample into a thread-local lock-free Ring Buffer
        with O(1) LRU temporal garbage collection.
        Executes variance filtering to discard SPAN port buffer bloat anomalies.
        """
        if not hasattr(self._thread_local, 'flow_ring'):
            self._thread_local.flow_ring = BoundedFlowWindowRing(max_flows=1024, max_window=32)

        history = self._thread_local.flow_ring.get_or_create(flow_key)
        current_sample = (timestamps["ts_val"],
                          timestamps["ts_ecr"], arrival_ns)
        eval_res = AdvancedSpatialProber.evaluate_passive_tcp_jitter(
            current_sample=current_sample,
            history=list(history),
            os_profile=os_profile,
        )
        history.append(current_sample)
        return eval_res

    def process_raw_frame(self, frame: bytes) -> DissectedFlowRecord:
        """
        Decodes a raw Ethernet frame, handles 802.1Q tags, ERSPAN GRE decapsulation,
        extracts L3/L4 conversation flows, and runs DPI protocol inspection.
        Enforces zero-lock thread-isolated statistics accumulation.
        """
        t_stats = self._get_thread_stats()
        t_stats.packets_captured += 1
        t_stats.bytes_captured += len(frame)

        if len(frame) < 14:
            return DissectedFlowRecord()

        dst_mac = ":".join(f"{b:02X}" for b in frame[0:6])
        src_mac = ":".join(f"{b:02X}" for b in frame[6:12])

        # 1. 802.1Q VLAN Tag Extraction
        vlan_id, ethertype, payload = VlanTagExtractor.extract_vlan(frame)
        if vlan_id is not None:
            t_stats.vlans_discovered.add(vlan_id)

        flow_data: Dict[str, Any] = {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "vlan_id": vlan_id,
            "ethertype": ethertype,
            "telemetry": {}
        }

        # 2. ARP Processing (EtherType 0x0806)
        if ethertype == 0x0806 and len(payload) >= 28:
            hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack(
                ">HHBBH", payload[:8])
            if hw_len == 6 and proto_len == 4:
                sender_mac = ":".join(f"{b:02X}" for b in payload[8:14])
                sender_ip = ".".join(str(b) for b in payload[14:18])
                target_ip = ".".join(str(b) for b in payload[24:28])

                flow_data["src_ip"] = sender_ip
                flow_data["dst_ip"] = target_ip
                flow_data["proto"] = "ARP"
                flow_data["opcode"] = "REQUEST" if opcode == 1 else (
                    "REPLY" if opcode == 2 else str(opcode))

                if _is_private_ip(sender_ip):
                    t_stats.active_hosts.add(sender_ip)
                t_stats.protocols_detected["ARP"] += 1

                if self.on_node_discovered and _is_private_ip(sender_ip):
                    self.on_node_discovered({
                        "ip": sender_ip,
                        "mac": sender_mac,
                        "vlan_id": vlan_id,
                        "discovery_method": "mirrored_span_arp"
                    })
                return DissectedFlowRecord(**flow_data)

        # 3. IPv4 Processing (EtherType 0x0800)
        elif ethertype == 0x0800 and len(payload) >= 20:
            version_ihl = payload[0]
            ihl = (version_ihl & 0x0F) * 4
            ip_proto = payload[9]
            src_ip = ".".join(str(b) for b in payload[12:16])
            dst_ip = ".".join(str(b) for b in payload[16:20])

            flow_data["src_ip"] = src_ip
            flow_data["dst_ip"] = dst_ip

            if _is_private_ip(src_ip):
                t_stats.active_hosts.add(src_ip)
            if _is_private_ip(dst_ip):
                t_stats.active_hosts.add(dst_ip)

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
                if tcp_data_offset < 20:
                    return DissectedFlowRecord(**flow_data)
                app_payload = payload[ihl + tcp_data_offset:]

                flow_data["proto"] = "TCP"
                flow_data["src_port"] = src_port
                flow_data["dst_port"] = dst_port

                t_stats.protocols_detected["TCP"] += 1

                # Extract full dynamic TCP header to capture RFC 7323 Options
                if len(payload) >= ihl + tcp_data_offset:
                    full_tcp_hdr = payload[ihl:ihl + tcp_data_offset]
                    timestamps = AdvancedSpatialProber.extract_tcp_timestamps(full_tcp_hdr)

                    if timestamps and timestamps.get("has_rfc7323"):
                        flow_key = (src_ip, dst_ip, src_port, dst_port)
                        # Microsecond Telemetry Synchronization (IEEE 1588 / OS fallback)
                        is_ptp = getattr(self, "ptp_capability", {}).get("ptp_supported", False)
                        if is_ptp and hasattr(time, 'CLOCK_TAI'):
                            arrival_ns = time.clock_gettime_ns(time.CLOCK_TAI)
                        else:
                            arrival_ns = time.perf_counter_ns()
                        jitter_eval = self._evaluate_span_jitter(flow_key, timestamps, arrival_ns)

                        spatial_jitter_payload: Dict[str, Any] = {
                            "ts_val": timestamps["ts_val"],
                            "ts_ecr": timestamps["ts_ecr"],
                            "raw_tcp_options_len": max(0, len(full_tcp_hdr) - 20),
                            "jitter_us": jitter_eval.get("jitter_us", 0.0),
                            "baseline_deduction_us": jitter_eval.get("baseline_deduction_us", 50.0),
                            "buffer_bloat_discard": jitter_eval.get("buffer_bloat_discard", False),
                            "ptp_hardware_timestamped": getattr(self, "ptp_capability", {}).get("ptp_supported", False),
                        }

                        # Compute spatial attenuation and cable flight only when not discarded for buffer bloat
                        if not jitter_eval.get("buffer_bloat_discard", False):
                            effective_flight_us = jitter_eval.get("median_arrival_us", 0.0) or jitter_eval.get("delta_arrival_us", 0.0)
                            atten_eval = AdvancedSpatialProber.calculate_spatial_attenuation(
                                flight_us=effective_flight_us,
                                baseline_deduction_us=jitter_eval.get("baseline_deduction_us", 50.0),
                            )
                            spatial_jitter_payload["spatial_attenuation_db"] = atten_eval["spatial_attenuation_db"]
                            spatial_jitter_payload["estimated_distance_m"] = atten_eval["estimated_distance_m"]
                            spatial_jitter_payload["tau_flight_ns"] = atten_eval["tau_flight_ns"]

                        flow_data.setdefault("telemetry", {})
                        flow_data["telemetry"]["spatial_jitter"] = spatial_jitter_payload

                # Inline Industrial OT Wire Dissection (Modbus TCP 502, Mercury MSP 3001)
                ot_res = None
                if src_port == 502 or dst_port == 502:
                    ot_res = OtWireDissector.dissect_modbus_tcp(app_payload)
                elif src_port == 3001 or dst_port == 3001 or (len(app_payload) >= 4 and app_payload[0] == 0x02 and b"READY" in app_payload):
                    ot_res = OtWireDissector.dissect_mercury_msp(app_payload)

                if ot_res:
                    flow_data["proto"] = "TCP"
                    t_stats.protocols_detected["MODBUS" if "MODBUS" in ot_res.get("protocol", "") else "MERCURY_MSP"] += 1
                    if "telemetry" in flow_data and isinstance(flow_data["telemetry"], dict):
                        if "spatial_jitter" in flow_data["telemetry"]:
                            ot_res["spatial_jitter"] = flow_data["telemetry"]["spatial_jitter"]
                    flow_data["telemetry"] = ot_res
                    self._dispatch_telemetry(src_ip, src_mac, dst_ip, vlan_id, ot_res)
                else:
                    # Deep Packet Inspection Fallback
                    dpi_res = DpiParser.parse_payload(app_payload, src_port, dst_port, "TCP")
                    if dpi_res:
                        telemetry_data = dpi_res.model_dump(exclude_none=True) if hasattr(dpi_res, "model_dump") else dict(dpi_res)
                        if "telemetry" in flow_data and isinstance(flow_data["telemetry"], dict):
                            if "spatial_jitter" in flow_data["telemetry"]:
                                telemetry_data["spatial_jitter"] = flow_data["telemetry"]["spatial_jitter"]
                        flow_data["telemetry"] = telemetry_data
                        self._dispatch_telemetry(src_ip, src_mac, dst_ip, vlan_id, dpi_res)

            # UDP (Protocol 17)
            elif ip_proto == 17 and len(payload) >= ihl + 8:
                udp_hdr = payload[ihl:ihl + 8]
                src_port, dst_port, udp_len = struct.unpack(">HHH", udp_hdr[:6])
                app_payload = payload[ihl + 8:ihl + udp_len]

                flow_data["proto"] = "UDP"
                flow_data["src_port"] = src_port
                flow_data["dst_port"] = dst_port

                t_stats.protocols_detected["UDP"] += 1

                # Inline Industrial OT Wire Dissection (BACnet/IP 47808)
                ot_res = None
                if src_port == 47808 or dst_port == 47808:
                    ot_res = OtWireDissector.dissect_bacnet_ip(app_payload)

                if ot_res:
                    flow_data["proto"] = "UDP"
                    t_stats.protocols_detected["BACNET_IP"] += 1
                    flow_data["telemetry"] = ot_res
                    self._dispatch_telemetry(src_ip, src_mac, dst_ip, vlan_id, ot_res)
                else:
                    # Deep Packet Inspection Fallback
                    dpi_res = DpiParser.parse_payload(app_payload, src_port, dst_port, "UDP")
                    if dpi_res:
                        telemetry_data = dpi_res.model_dump(exclude_none=True) if hasattr(dpi_res, "model_dump") else dict(dpi_res)
                        flow_data["telemetry"] = telemetry_data
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

        return DissectedFlowRecord(**flow_data)

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

        # Modbus Industrial Telemetry
        elif dpi.get("protocol") in ("MODBUS", "MODBUS_TCP"):
            target_ip = dst_ip if _is_private_ip(dst_ip) else src_ip
            target_mac = src_mac
            if _is_private_ip(target_ip):
                self.on_node_discovered({
                    "ip": target_ip,
                    "mac": target_mac,
                    "vendor": "Modbus Industrial Device",
                    "model": f"Modbus PLC (Unit ID {dpi.get('unit_id', 1)})",
                    "type": "plc",
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_modbus"
                })

        # Mercury MSP Access Controller Telemetry
        elif dpi.get("protocol") == "MERCURY_MSP":
            target_ip = src_ip if _is_private_ip(src_ip) else (dst_ip if _is_private_ip(dst_ip) else "")
            target_mac = src_mac
            if target_ip or target_mac:
                self.on_node_discovered({
                    "ip": target_ip,
                    "mac": target_mac,
                    "vendor": "Mercury Security",
                    "model": dpi.get("model", "Mercury Security Access Controller"),
                    "type": "access_controller",
                    "vlan_id": vlan_id,
                    "discovery_method": "mirrored_span_mercury"
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
        """Starts background promiscuous / SPAN packet capture loop with zero-copy BPF AsyncSniffer."""
        if self._running:
            return
        self.interface = interface or self.interface
        self._running = True

        # 1. Asynchronous Scapy AsyncSniffer with zero-copy BPF filtering
        bpf_filter = "tcp or udp or arp or ether proto 0x8892 or ether host 01:80:c2:00:00:00 or ether host 01:80:c2:00:00:0e or ether host 01:00:0c:cc:cc:cc"
        try:
            from scapy.sendrecv import AsyncSniffer
            def _scapy_cb(pkt):
                if not self._running:
                    return
                try:
                    self.process_raw_frame(bytes(pkt))
                except Exception:
                    pass

            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=bpf_filter,
                prn=_scapy_cb,
                store=False
            )
            self._sniffer.start()
            return
        except Exception:
            self._sniffer = None

        # 2. Fallback to Windows SIO_RCVALL raw socket
        def _capture_loop():
            try:
                import socket
                from core.device_classifier import LocationEngine
                loc = LocationEngine.get_local_location()
                local_ip = loc.get("local_ip", "0.0.0.0")

                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((local_ip, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                try:
                    s.setsockopt(socket.SOL_SOCKET, 37, (1 << 6) | (1 << 4))
                except OSError:
                    pass

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
        """Stops live capture loop and tears down sniffer."""
        self._running = False
        if getattr(self, "_sniffer", None) and self._sniffer.running:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    def get_summary_stats(self) -> MirrorCaptureSummary:
        """Returns snapshot of current mirrored traffic statistics."""
        return MirrorCaptureSummary(
            packets_captured=self.stats["packets_captured"],
            bytes_captured=self.stats["bytes_captured"],
            vlans_discovered=sorted(list(self.stats["vlans_discovered"])),
            protocols_detected=dict(self.stats["protocols_detected"]),
            active_hosts_count=len(self.stats["active_hosts"]),
            ptp_hardware_timestamping=dict(getattr(self, "ptp_capability", {})),
        )


__all__ = [
    "SpanCaptureEngine",
    "MirrorEnginePort",
    "DissectedFlowRecord",
    "MirrorCaptureSummary",
    "VlanTagExtractor",
    "ErspanDecapsulator",
    "OtWireDissector",
    "ZeroLockStatsProxy",
    "BoundedFlowWindowRing",
    "_MappingCompatibleModel",
]


