"""Infrastructure compatibility bridge for legacy AETHERIS prober imports.

This module owns all transport-facing probe implementations and the dynamic
sys.modules aliases required by legacy callers. Core code imports only the
contracts from ``aetheris.core.ports.legacy_probe_port``.
"""

import importlib.util
import os
import re
import socket
import struct
import sys
import time
import types
from collections import defaultdict
from typing import Any, Dict, List, Optional

from aetheris.core.ports.legacy_probe_port import (
    AetherisProbeRegistry,
    BaseAetherisProbe,
)


# Preserve the historical package path while keeping transport code in this adapter.
probers_pkg = types.ModuleType("aetheris.core.probers")
probers_pkg.__package__ = "aetheris.core.probers"
probers_pkg.__path__ = []
sys.modules["aetheris.core.probers"] = probers_pkg

_sanit_path = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../core/parsers/sanitization.py")
)
if "aetheris.core.parsers.sanitization" not in sys.modules:
    _sanit_spec = importlib.util.spec_from_file_location(
        "aetheris.core.parsers.sanitization", _sanit_path
    )
    _sanitization_parser = importlib.util.module_from_spec(_sanit_spec)
    sys.modules["aetheris.core.parsers.sanitization"] = _sanitization_parser
    sys.modules["aetheris.core.probers.sanitization"] = _sanitization_parser
    _sanit_spec.loader.exec_module(_sanitization_parser)
else:
    _sanitization_parser = sys.modules["aetheris.core.parsers.sanitization"]
    sys.modules["aetheris.core.probers.sanitization"] = _sanitization_parser

from aetheris.core.parsers.sanitization import clean_ascii_string, sanitize_prober_payload

from aetheris.infrastructure.adapters.chassis_probe import ChassisIntelligenceProbe
from aetheris.infrastructure.adapters.snmp_fdb_adapter import SnmpFdbAdapter
from aetheris.infrastructure.adapters.tcp_zero_window_adapter import TcpZeroWindowAdapter


class _ProbersFinder:
    @classmethod
    def find_spec(cls, fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname == "aetheris.core.probers" or fullname.startswith("aetheris.core.probers."):
            if fullname in sys.modules:
                from importlib.machinery import ModuleSpec

                mod = sys.modules[fullname]
                is_pkg = hasattr(mod, "__path__") and mod.__path__ is not None
                return ModuleSpec(
                    fullname,
                    None,
                    is_package=is_pkg,
                    origin="dynamic_infrastructure_bridge",
                )
        return None


if not any(getattr(item, "__name__", "") == "_ProbersFinder" for item in sys.meta_path):
    sys.meta_path.insert(0, _ProbersFinder)


class SpanningTreeTelemetryProbe:
    """Compatibility facade for stateless 802.1t bridge priority calculations."""

    def __init__(self) -> None:
        self.results: Dict[str, Dict[str, Any]] = {}

    def _stp_callback(self, packet: Any) -> None:
        from scapy.layers.l2 import STP

        if packet.haslayer(STP):
            stp_layer = packet[STP]
            try:
                rootid = getattr(stp_layer, "rootid", 0)
                bridgeid = getattr(stp_layer, "bridgeid", 0)
                pathcost = getattr(stp_layer, "pathcost", 0)
                rootid_val = int(rootid) if isinstance(rootid, (int, float, str)) else 0
                bridgeid_val = int(bridgeid) if isinstance(bridgeid, (int, float, str)) else 0
                pathcost_val = int(pathcost) if isinstance(pathcost, (int, float, str)) else 0
                bridgeprio = getattr(stp_layer, "bridgeprio", None)
                bridge_prio_val = (
                    int(bridgeprio)
                    if bridgeprio is not None and isinstance(bridgeprio, (int, float, str))
                    else (bridgeid_val >> 48) & 0xFFFF
                )
                self.results[packet.src] = {
                    "rootid": rootid_val,
                    "bridgeid": bridgeid_val,
                    "pathcost": pathcost_val,
                    "bridge_priority": bridge_prio_val,
                    "vlan_id": bridge_prio_val & 0x0FFF,
                }
            except Exception:
                pass

    _bpdu_callback = _stp_callback


class MulticastIdentityProbe(BaseAetherisProbe):
    """Compatibility facade for the legacy multicast identity probe."""

    def __init__(
        self,
        target_ip: str = "224.0.0.251",
        telemetry_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(target_ip, telemetry_context or {})
        self.interface = self.telemetry_context.get("span_interface", "eth0")
        self.capture_duration = self.telemetry_context.get("capture_duration_sec", 65.0)
        self.identity_matrix: Dict[str, Dict[str, Any]] = {}

    def _multicast_callback(self, packet: Any) -> None:
        from scapy.all import DNS, Ether, Raw

        mac_src = (
            packet[Ether].src
            if packet.haslayer(Ether)
            else getattr(packet, "src", "00:00:00:00:00:00")
        ) or "00:00:00:00:00:00"
        if mac_src not in self.identity_matrix:
            self.identity_matrix[mac_src] = {"mdns_services": set(), "ssdp_headers": set()}

        if packet.haslayer(DNS) and hasattr(packet[DNS], "an") and packet[DNS].an:
            try:
                for rr in packet[DNS].an:
                    if hasattr(rr, "rrname"):
                        service_name = (
                            rr.rrname.decode("utf-8", errors="ignore")
                            if isinstance(rr.rrname, bytes)
                            else (str(rr.rrname) if rr.rrname is not None else "")
                        )
                        rdata_val = getattr(rr, "rdata", "")
                        service_data = (
                            rdata_val.decode("utf-8", errors="ignore")
                            if isinstance(rdata_val, bytes)
                            else (str(rdata_val) if rdata_val is not None else "")
                        )
                        if service_name:
                            self.identity_matrix[mac_src]["mdns_services"].add(service_name)
                        if service_data:
                            self.identity_matrix[mac_src]["mdns_services"].add(service_data)
                    current = getattr(rr, "payload", None)
                    while current and hasattr(current, "rrname"):
                        current_name = (
                            current.rrname.decode("utf-8", errors="ignore")
                            if isinstance(current.rrname, bytes)
                            else str(current.rrname)
                        )
                        current_data = (
                            current.rdata.decode("utf-8", errors="ignore")
                            if hasattr(current, "rdata") and isinstance(current.rdata, bytes)
                            else str(getattr(current, "rdata", ""))
                        )
                        if current_name:
                            self.identity_matrix[mac_src]["mdns_services"].add(current_name)
                        if current_data:
                            self.identity_matrix[mac_src]["mdns_services"].add(current_data)
                        current = getattr(current, "payload", None)
            except Exception:
                pass

        if packet.haslayer(Raw):
            try:
                raw_payload = packet[Raw].load
                payload = (
                    raw_payload.decode("utf-8", errors="ignore")
                    if isinstance(raw_payload, bytes)
                    else str(raw_payload)
                )
                match = re.search(r"(?i)(?:Server|User-Agent):\s*(.+)", payload)
                if match:
                    self.identity_matrix[mac_src]["ssdp_headers"].add(match.group(1).strip())
            except Exception:
                pass

    async def execute(self) -> Dict[str, Any]:
        return self.identity_matrix

    async def rollback(self) -> bool:
        self.identity_matrix.clear()
        return True


class TCPClockSkewProbe(BaseAetherisProbe):
    """Compatibility facade for the legacy TCP clock skew probe."""

    def __init__(
        self,
        target_ip: str = "0.0.0.0",
        telemetry_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(target_ip, telemetry_context or {})
        self.probe_id = "L3-TCP-SKEW-NAT-001"
        self.interface = self.telemetry_context.get("span_interface", "Ethernet 2")
        self.capture_duration = self.telemetry_context.get("capture_duration_sec", 30.0)
        self.flow_matrix: Dict[int, List[Any]] = defaultdict(list)

    def _frame_callback(self, packet: Any) -> None:
        from scapy.all import IP, TCP

        if packet.haslayer(IP) and packet.haslayer(TCP):
            if self.target_ip and self.target_ip != "0.0.0.0" and packet[IP].src != self.target_ip:
                return
            sport = packet[TCP].sport
            ts_opt = next(
                (option[1] for option in packet[TCP].options
                 if isinstance(option, tuple) and option[0] == "Timestamp"),
                None,
            )
            if ts_opt and isinstance(ts_opt, tuple) and len(ts_opt) == 2:
                self.flow_matrix[sport].append((time.perf_counter(), ts_opt[0]))

    def _calculate_clock_entropy(self) -> Dict[str, Any]:
        if not self.flow_matrix:
            return {"status": "INSUFFICIENT_TELEMETRY"}

        distinct_clocks: List[int] = []
        clock_frequencies: List[float] = []
        for observations in self.flow_matrix.values():
            if len(observations) < 5:
                continue
            valid_intervals: List[Any] = []
            for index in range(1, len(observations)):
                dt = observations[index][0] - observations[index - 1][0]
                dts = observations[index][1] - observations[index - 1][1]
                if dt > 0 and dts >= 0:
                    valid_intervals.append((dt, dts))
            if len(valid_intervals) < 4:
                continue
            valid_intervals.sort(key=lambda item: item[0])
            filtered = valid_intervals[:max(1, int(len(valid_intervals) * 0.95))]
            total_dt = sum(item[0] for item in filtered)
            total_dts = sum(item[1] for item in filtered)
            if total_dt > 0:
                distinct_clocks.append(observations[0][1])
                clock_frequencies.append(round(total_dts / total_dt, 2))

        if not distinct_clocks:
            return {"status": "PENDING_CONCURRENT_FLOWS"}
        max_ts_offset = max(distinct_clocks) - min(distinct_clocks)
        return {
            "status": "LOCKED",
            "active_ephemeral_flows": len(distinct_clocks),
            "clock_spread_ticks": max_ts_offset,
            "detected_kernel_frequencies_hz": clock_frequencies,
            "hidden_nat_detected": max_ts_offset > 1000000
            or len({round(frequency, -1) for frequency in clock_frequencies}) > 1,
        }

    async def execute(self) -> Dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "target_ip": self.target_ip,
            "entropy_matrix": self._calculate_clock_entropy(),
        }

    async def rollback(self) -> bool:
        self.flow_matrix.clear()
        return True


def _icmp_checksum(data: bytes) -> int:
    """Compute the RFC 1071 Internet checksum for an ICMP packet."""
    if len(data) % 2:
        data += b"\x00"
    checksum = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    return ~checksum & 0xFFFF


def _build_icmp_echo(identifier: int, seq: int) -> bytes:
    """Construct an ICMP Echo Request with an RFC 1071 checksum."""
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, seq)
    payload = b"AETHERIS" * 4
    checksum = _icmp_checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, checksum, identifier, seq) + payload


class ActiveTTLInterrogator:
    """Compatibility facade for the legacy active TTL interrogator."""

    def __init__(
        self,
        target_ips: List[str],
        timeout: float = 0.5,
        telemetry_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.target_ips = target_ips
        self.telemetry_context = telemetry_context or {}
        self.timeout = min(
            0.5,
            self.telemetry_context.get("timeout_sec", timeout if timeout is not None else 0.5),
        )
        self._identifier = os.getpid() & 0xFFFF

    def _determine_baseline(self, returning_ttl: int) -> int:
        for baseline in [64, 128, 255]:
            if returning_ttl <= baseline:
                return baseline
        return 255

    def _fallback_sweep(self) -> Dict[str, int]:
        results: Dict[str, int] = {}
        for ip in self.target_ips:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, 80))
                ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                results[ip] = self._determine_baseline(ttl) - ttl
                sock.close()
            except Exception:
                results[ip] = 0
        return results

    def _concurrent_raw_sweep(self) -> Dict[str, int]:
        results: Dict[str, int] = {}
        seq_to_ip: Dict[int, str] = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
        except (PermissionError, OSError):
            return self._fallback_sweep()

        try:
            for seq, target_ip in enumerate(self.target_ips):
                seq_to_ip[seq] = target_ip
                try:
                    sock.sendto(_build_icmp_echo(self._identifier, seq), (target_ip, 0))
                except Exception:
                    pass
            start_time = time.time()
            while seq_to_ip and (time.time() - start_time) < self.timeout:
                try:
                    data, address = sock.recvfrom(1024)
                    ip = address[0]
                    if ip in self.target_ips and len(data) >= 28:
                        results[ip] = self._determine_baseline(data[8]) - data[8]
                        for seq, target in list(seq_to_ip.items()):
                            if target == ip:
                                del seq_to_ip[seq]
                except socket.timeout:
                    break
                except Exception:
                    pass
        finally:
            sock.close()

        for ip in self.target_ips:
            if ip not in results:
                results[ip] = 0
        return results

    async def execute(self) -> Dict[str, Any]:
        return {"ttl_matrix": self._concurrent_raw_sweep()}

    async def rollback(self) -> bool:
        return True


class ActiveCAMExtractor:
    """Compatibility facade delegating to SnmpFdbAdapter."""

    def __init__(
        self,
        target_ip: str,
        v3_user: str = "",
        v3_auth: str = "",
        v3_priv: str = "",
        telemetry_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.target_ip = target_ip
        self.telemetry_context = telemetry_context or {}
        self.adapter = SnmpFdbAdapter(
            target_ip=target_ip,
            v3_user=v3_user,
            v3_auth=v3_auth,
            v3_priv=v3_priv,
            telemetry_context=self.telemetry_context,
        )
        self.snmp_engine = self.adapter.engine

    def close(self) -> None:
        self.adapter.close()

    async def __aenter__(self) -> "ActiveCAMExtractor":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        self.close()
        return False

    async def execute_cam_extraction(self) -> Dict[str, str]:
        return await self.adapter.extract_cam_matrix(self.target_ip)


class TCPZeroWindowProbe:
    """Compatibility facade delegating to TcpZeroWindowAdapter."""

    def __init__(self, target_ip: str, telemetry_context: Optional[Dict[str, Any]] = None):
        self.target_ip = target_ip
        self.telemetry_context = telemetry_context or {}
        self.probe_id = "L3-TCP-ZEROWINDOW-001"
        self.interface = self.telemetry_context.get("span_interface", "Ethernet 2")
        self.capture_duration = self.telemetry_context.get("capture_duration_sec", 45.0)
        self.adapter = TcpZeroWindowAdapter(
            event_bus=None,
            interface=self.interface,
            timeout=self.capture_duration,
        )
        self.collapse_matrix = self.adapter.collapse_matrix

    def _frame_callback(self, packet: Any) -> None:
        self.adapter._on_packet(packet)

    async def execute(self) -> Dict[str, Any]:
        telemetry = await self.adapter.monitor_target(
            self.target_ip,
            duration=self.capture_duration,
        )
        if telemetry.status in ("NOMINAL_BUFFER_STATE", "TRANSIENT_MICRO_STALLS_DETECTED"):
            return {"probe_id": self.probe_id, "status": telemetry.status}
        return {
            "probe_id": self.probe_id,
            "status": telemetry.status,
            "capture_duration_sec": telemetry.capture_duration_sec,
            "exhaustion_matrix": telemetry.exhaustion_matrix,
            "event_vector": telemetry.event_vector,
        }

    async def rollback(self) -> bool:
        self.collapse_matrix.clear()
        return True

    async def __aenter__(self) -> "TCPZeroWindowProbe":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        await self.rollback()
        return False


def install_prober_compatibility_bridges() -> None:
    """Populate legacy dynamic module mappings and compatibility exports."""
    import aetheris.core.parsers.chassis_parser as chassis_parser
    import aetheris.core.parsers.cldap_parser as cldap_parser
    import aetheris.core.parsers.industrial_parser as industrial_parser
    import aetheris.core.parsers.mercury_parser as mercury_parser
    import aetheris.core.parsers.onvif_parser as onvif_parser
    import aetheris.core.parsers.sanitization as sanitization
    import aetheris.core.parsers.span_parser as span_parser
    import aetheris.core.parsers.stealth_parser as stealth_parser
    import aetheris.core.parsers.tcp_window_parser as tcp_window_parser
    import aetheris.infrastructure.adapters.span_tap_adapter as span_tap_adapter

    probers_pkg.BaseAetherisProbe = BaseAetherisProbe
    probers_pkg.AetherisProbeRegistry = AetherisProbeRegistry
    probers_pkg.SpanningTreeTelemetryProbe = SpanningTreeTelemetryProbe
    probers_pkg.MulticastIdentityProbe = MulticastIdentityProbe
    probers_pkg.TCPClockSkewProbe = TCPClockSkewProbe
    probers_pkg.ActiveTTLInterrogator = ActiveTTLInterrogator
    probers_pkg._icmp_checksum = _icmp_checksum
    probers_pkg._build_icmp_echo = _build_icmp_echo
    probers_pkg.ActiveCAMExtractor = ActiveCAMExtractor
    probers_pkg.TCPZeroWindowProbe = TCPZeroWindowProbe
    probers_pkg.ChassisIntelligenceProbe = ChassisIntelligenceProbe
    probers_pkg.SpanCaptureEngine = span_tap_adapter.SpanTapAdapter
    probers_pkg.SpanTapAdapter = span_tap_adapter.SpanTapAdapter

    for name in (
        "BACNET_READ_PROPERTY_INQUIRY", "parse_bacnet_response", "probe_bacnet_device",
        "MODBUS_READ_DEVICE_ID", "parse_modbus_mei_response", "probe_modbus_device",
        "probe_modbus_diagnostics", "probe_ethernet_ip_cip", "probe_siemens_s7",
        "probe_industrial_host",
    ):
        setattr(probers_pkg, name, getattr(industrial_parser, name))
    for name in (
        "calculate_z_axis", "process_lldp_frame", "extract_lldp_med_telemetry",
        "AWG23_RESISTANCE_KM", "POE_CURRENT_AMPS", "MOCK_RX_DRAW_WATTS",
    ):
        setattr(probers_pkg, name, getattr(chassis_parser, name))
    for name in (
        "probe_mercury_panel", "parse_mercury_response", "MERCURY_STATUS_INQUIRY",
        "KNOWN_MERCURY_MODELS", "parse_msp_frame", "MSPParser", "ACK_PAYLOAD",
    ):
        setattr(probers_pkg, name, getattr(mercury_parser, name))
    for name in (
        "probe_onvif_camera", "parse_onvif_device_information_xml",
        "ONVIF_SOAP_GET_DEVICE_INFORMATION",
    ):
        setattr(probers_pkg, name, getattr(onvif_parser, name))
    for name in (
        "probe_netbios", "probe_ws_discovery", "probe_llmnr", "probe_stealth_host",
        "NETBIOS_NBSTAT_QUERY",
    ):
        setattr(probers_pkg, name, getattr(stealth_parser, name))
    for name in ("probe_cldap_endpoint", "build_cldap_netlogon_ping", "parse_cldap_response"):
        setattr(probers_pkg, name, getattr(cldap_parser, name))
    probers_pkg.sanitize_prober_payload = sanitization.sanitize_prober_payload
    probers_pkg.clean_ascii_string = sanitization.clean_ascii_string

    base_probe_mod = types.ModuleType("aetheris.core.probers.base_probe")
    base_probe_mod.BaseAetherisProbe = BaseAetherisProbe
    sys.modules[base_probe_mod.__name__] = base_probe_mod
    probers_pkg.base_probe = base_probe_mod

    registry_mod = types.ModuleType("aetheris.core.probers.registry")
    registry_mod.AetherisProbeRegistry = AetherisProbeRegistry
    sys.modules[registry_mod.__name__] = registry_mod
    probers_pkg.registry = registry_mod

    bacnet_mod = types.ModuleType("aetheris.core.probers.bacnet_probe")
    for name in ("BACNET_READ_PROPERTY_INQUIRY", "parse_bacnet_response", "probe_bacnet_device"):
        setattr(bacnet_mod, name, getattr(industrial_parser, name))
    sys.modules[bacnet_mod.__name__] = bacnet_mod
    probers_pkg.bacnet_probe = bacnet_mod

    lldp_mod = types.ModuleType("aetheris.core.probers.lldp_parser")
    for name in (
        "calculate_z_axis", "process_lldp_frame", "extract_lldp_med_telemetry",
        "AWG23_RESISTANCE_KM", "POE_CURRENT_AMPS", "MOCK_RX_DRAW_WATTS",
    ):
        setattr(lldp_mod, name, getattr(chassis_parser, name))
    sys.modules[lldp_mod.__name__] = lldp_mod
    probers_pkg.lldp_parser = lldp_mod

    for alias in ("industrial_prober", "modbus_probe"):
        sys.modules[f"aetheris.core.probers.{alias}"] = industrial_parser
        setattr(probers_pkg, alias, industrial_parser)
    for alias in ("mercury_probe", "mercury_msp_parser"):
        sys.modules[f"aetheris.core.probers.{alias}"] = mercury_parser
        setattr(probers_pkg, alias, mercury_parser)
    sys.modules["aetheris.core.parsers.mercury_msp_parser"] = mercury_parser
    sys.modules["aetheris.core.probers.onvif_probe"] = onvif_parser
    probers_pkg.onvif_probe = onvif_parser
    sys.modules["aetheris.core.probers.stealth_probe"] = stealth_parser
    probers_pkg.stealth_probe = stealth_parser
    for alias in ("cldap", "cldap_discovery"):
        sys.modules[f"aetheris.core.probers.{alias}"] = cldap_parser
        setattr(probers_pkg, alias, cldap_parser)
    sys.modules["aetheris.core.probers.span_engine"] = span_tap_adapter
    probers_pkg.span_engine = span_tap_adapter

    snmp_cam_mod = types.ModuleType("aetheris.core.probers.snmp_cam_extractor")
    snmp_cam_mod.ActiveCAMExtractor = ActiveCAMExtractor
    sys.modules[snmp_cam_mod.__name__] = snmp_cam_mod
    sys.modules["aetheris.discovery.snmp_cam_extractor"] = snmp_cam_mod
    probers_pkg.snmp_cam_extractor = snmp_cam_mod

    zero_window_mod = types.ModuleType("aetheris.core.probers.zero_window_probe")
    zero_window_mod.TCPZeroWindowProbe = TCPZeroWindowProbe
    sys.modules[zero_window_mod.__name__] = zero_window_mod
    probers_pkg.zero_window_probe = zero_window_mod

    l2_physical_mod = types.ModuleType("aetheris.core.probers.l2_physical")
    l2_physical_mod.__package__ = l2_physical_mod.__name__
    l2_physical_mod.__path__ = []
    l2_physical_mod.SpanningTreeTelemetryProbe = SpanningTreeTelemetryProbe
    l2_physical_mod.ChassisIntelligenceProbe = ChassisIntelligenceProbe
    stp_mod = types.ModuleType("aetheris.core.probers.l2_physical.stp_intelligence")
    stp_mod.SpanningTreeTelemetryProbe = SpanningTreeTelemetryProbe
    sys.modules[stp_mod.__name__] = stp_mod
    l2_physical_mod.stp_intelligence = stp_mod
    chassis_probe_mod = types.ModuleType(
        "aetheris.core.probers.l2_physical.chassis_intelligence_probe"
    )
    chassis_probe_mod.ChassisIntelligenceProbe = ChassisIntelligenceProbe
    sys.modules[chassis_probe_mod.__name__] = chassis_probe_mod
    l2_physical_mod.chassis_intelligence_probe = chassis_probe_mod
    sys.modules[l2_physical_mod.__name__] = l2_physical_mod
    probers_pkg.l2_physical = l2_physical_mod

    l3_network_mod = types.ModuleType("aetheris.core.probers.l3_network")
    l3_network_mod.__package__ = l3_network_mod.__name__
    l3_network_mod.__path__ = []
    l3_network_mod.MulticastIdentityProbe = MulticastIdentityProbe
    l3_network_mod.TCPClockSkewProbe = TCPClockSkewProbe
    l3_network_mod.ActiveTTLInterrogator = ActiveTTLInterrogator
    l3_network_mod._icmp_checksum = _icmp_checksum
    l3_network_mod._build_icmp_echo = _build_icmp_echo

    multicast_mod = types.ModuleType(
        "aetheris.core.probers.l3_network.multicast_identity"
    )
    multicast_mod.MulticastIdentityProbe = MulticastIdentityProbe
    sys.modules[multicast_mod.__name__] = multicast_mod
    l3_network_mod.multicast_identity = multicast_mod

    tcp_skew_mod = types.ModuleType("aetheris.core.probers.l3_network.tcp_skew_probe")
    tcp_skew_mod.TCPClockSkewProbe = TCPClockSkewProbe
    sys.modules[tcp_skew_mod.__name__] = tcp_skew_mod
    sys.modules["aetheris.core.probers.tcp_clock_skew_probe"] = tcp_skew_mod
    l3_network_mod.tcp_skew_probe = tcp_skew_mod
    probers_pkg.tcp_clock_skew_probe = tcp_skew_mod

    ttl_mod = types.ModuleType("aetheris.core.probers.l3_network.ttl_interrogator")
    ttl_mod.ActiveTTLInterrogator = ActiveTTLInterrogator
    ttl_mod._icmp_checksum = _icmp_checksum
    ttl_mod._build_icmp_echo = _build_icmp_echo
    sys.modules[ttl_mod.__name__] = ttl_mod
    sys.modules["aetheris.core.probers.active_ttl_interrogator"] = ttl_mod
    l3_network_mod.ttl_interrogator = ttl_mod
    probers_pkg.active_ttl_interrogator = ttl_mod
    sys.modules[l3_network_mod.__name__] = l3_network_mod
    probers_pkg.l3_network = l3_network_mod

    if "aetheris.core" in sys.modules:
        sys.modules["aetheris.core"].probers = probers_pkg


__all__ = [
    "ActiveCAMExtractor", "ActiveTTLInterrogator", "AetherisProbeRegistry",
    "BaseAetherisProbe", "MulticastIdentityProbe", "SpanningTreeTelemetryProbe",
    "TCPClockSkewProbe", "TCPZeroWindowProbe", "install_prober_compatibility_bridges",
    "_build_icmp_echo", "_icmp_checksum",
]

install_prober_compatibility_bridges()
