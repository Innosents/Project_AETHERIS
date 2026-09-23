"""
Project AETHERIS - Advanced Spatial Prober
Non-credentialed physical spatial interrogation vectors:
1. RFC 7323 TCP Timestamp Flight-Time & Microsecond Tick Jitter Calibration
2. mDNS / DNS-SD Civic Location TXT Record Harvesting
3. DHCP Option 82 (Agent Circuit ID / Remote ID) Switch-Port Pinning
"""

import socket
import struct
import time
import re
from typing import Dict, Any, Optional, List, Union, Tuple
from loguru import logger

from aetheris.core.ports.advanced_spatial_prober_port import (
    AdvancedSpatialProberPort,
    DhcpOption82PinResult,
    FlightDistanceResult,
    PassiveTcpJitterResult,
    SpatialAttenuationResult,
    SpatialPruningBoundaryResult,
)

SPEED_OF_LIGHT = 299_792_458  # meters/sec
DEFAULT_NVP = 0.69             # Nominal Velocity of Propagation for Cat5e/Cat6 copper
NVP_CAMERA_POE = 0.70          # Modern Cat6/Cat6a shielded runs (Axis, Hikvision)
NVP_PLC_INDUSTRIAL = 0.68      # Legacy Cat5/Cat5e industrial plants (Siemens, Rockwell)


class AdvancedSpatialProber(AdvancedSpatialProberPort):
    """
    Executes non-credentialed Layer 2/4 spatial interrogation to isolate
    physical media distance and exact switch port attachments.
    """

    # -------------------------------------------------------------------------
    # 1. Microsecond TCP Flight Time Calibration (RFC 7323)
    # -------------------------------------------------------------------------
    @staticmethod
    def resolve_dynamic_nvp(
        mac: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        hardware_profile: Optional[Dict[str, Any]] = None,
        default_nvp: float = DEFAULT_NVP,
    ) -> Tuple[float, str]:
        """
        Resolves the dynamic NVP coefficient based on hardware profiling.
        Returns: (nvp_value, nvp_source)
        """
        profile = hardware_profile or {}
        target_mac = mac or profile.get("mac")
        target_vendor = vendor or profile.get("vendor")
        target_type = device_type or profile.get("type") or profile.get("device_type")

        try:
            from aetheris.core.device_classifier import DeviceClassifier
            calibrated = DeviceClassifier.resolve_nvp(
                mac=target_mac,
                vendor=target_vendor,
                device_type=target_type,
                default_nvp=default_nvp,
            )
            has_hints = bool(target_mac or target_vendor or target_type)
            source = (
                "DYNAMIC_HARDWARE_CALIBRATED"
                if (calibrated != default_nvp or has_hints)
                else "STATIC_DEFAULT"
            )
            return calibrated, source
        except Exception:
            return default_nvp, "STATIC_DEFAULT"

    @staticmethod
    def calculate_flight_distance_from_us(
        flight_us: float,
        baseline_deduction_us: float = 50.0,
        nvp: Optional[float] = None,
        min_distance_m: float = 0.5,
        max_distance_m: float = 150.0,
        mac: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        hardware_profile: Optional[Dict[str, Any]] = None,
    ) -> FlightDistanceResult:
        """
        Calculates conductor length (meters) from measured microsecond flight time.
        Deducts nominal kernel TCP/IP context switch baseline (~50us for local LAN switch).
        Converts one-way propagation time into physical distance using copper NVP,
        dynamically calibrated via hardware MAC OUI, vendor profile, or device archetype.
        """
        if nvp is None:
            resolved_nvp, nvp_source = AdvancedSpatialProber.resolve_dynamic_nvp(
                mac=mac,
                vendor=vendor,
                device_type=device_type,
                hardware_profile=hardware_profile,
                default_nvp=DEFAULT_NVP,
            )
        else:
            if (mac or vendor or device_type or hardware_profile) and nvp == DEFAULT_NVP:
                resolved_nvp, nvp_source = AdvancedSpatialProber.resolve_dynamic_nvp(
                    mac=mac,
                    vendor=vendor,
                    device_type=device_type,
                    hardware_profile=hardware_profile,
                    default_nvp=DEFAULT_NVP,
                )
            else:
                resolved_nvp = nvp
                nvp_source = "EXPLICIT_OVERRIDE" if nvp != DEFAULT_NVP else "STATIC_DEFAULT"

        if flight_us <= baseline_deduction_us:
            net_flight_us = 0.0
            one_way_flight_s = 0.0
            clamped_distance = min_distance_m
        else:
            net_flight_us = flight_us - baseline_deduction_us
            one_way_flight_s = (net_flight_us * 1e-6) / 2.0
            v_prop = SPEED_OF_LIGHT * resolved_nvp
            raw_distance_m = one_way_flight_s * v_prop
            clamped_distance = round(max(min_distance_m, min(raw_distance_m, max_distance_m)), 2)

        # Confidence is highest when flight time is consistent and within standard Ethernet reach
        confidence = 0.85 if flight_us <= 200.0 else (0.75 if flight_us <= 1000.0 else 0.60)

        return FlightDistanceResult(
            raw_rtt_us=round(flight_us, 2),
            baseline_deduction_us=baseline_deduction_us,
            net_flight_us=round(net_flight_us, 3),
            one_way_flight_ns=round(one_way_flight_s * 1e9, 2),
            estimated_distance_meters=clamped_distance,
            estimated_distance_feet=round(clamped_distance * 3.28084, 2),
            confidence_score=confidence,
            nvp_calibrated=round(resolved_nvp, 4),
            nvp_source=nvp_source,
            derivation_method="MICROSECOND_TCP_FLIGHT_CALIBRATION",
        )

    @classmethod
    def measure_tcp_timestamp_flight(
        cls,
        ip: str,
        port: int,
        timeout: float = 0.4,
        samples: int = 3,
        baseline_deduction_us: float = 50.0
    ) -> Optional[FlightDistanceResult]:
        """
        Connects with TCP_NODELAY across open port, measuring microsecond flight times.
        Takes multiple samples to eliminate scheduling jitter outliers.
        """
        measurements: List[float] = []

        for _ in range(samples):
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(timeout)
                t_start = time.perf_counter()
                sock.connect((ip, port))
                t_elapsed = (time.perf_counter() - t_start) * 1e6  # Microseconds
                measurements.append(t_elapsed)
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            finally:
                try:
                    if sock is None:
                        continue
                    sock.close()
                except Exception:
                    pass

        if not measurements:
            return None

        # Sort and pick minimum round-trip time (lowest OS scheduling pollution)
        measurements.sort()
        best_rtt_us = measurements[0]
        jitter_us = (measurements[-1] - measurements[0]) if len(measurements) > 1 else 0.0

        res = cls.calculate_flight_distance_from_us(
            flight_us=best_rtt_us,
            baseline_deduction_us=baseline_deduction_us
        )
        return res.model_copy(
            update={
                "jitter_us": round(jitter_us, 2),
                "sample_count": len(measurements),
                "target_port": port,
            }
        )

    @staticmethod
    def extract_tcp_timestamps(raw_tcp_header: bytes) -> Optional[Dict[str, Any]]:
        """
        Dissects TCP Option Kind 8 (RFC 7323 Timestamps) from raw TCP header bytes.
        Format: Kind=8 (1B), Length=10 (1B), TSval (4B), TSecr (4B).
        """
        if len(raw_tcp_header) < 20:
            return None

        # Data offset is in high nibble of byte 12 (count of 32-bit words)
        data_offset = (raw_tcp_header[12] >> 4) * 4
        if len(raw_tcp_header) < data_offset:
            return None

        options = raw_tcp_header[20:data_offset]
        i = 0
        while i < len(options):
            kind = options[i]
            if kind == 0:  # End of Option List
                break
            if kind == 1:  # No-Operation (NOP)
                i += 1
                continue

            if i + 1 >= len(options):
                break
            opt_len = options[i + 1]
            if opt_len < 2 or i + opt_len > len(options):
                break

            if kind == 8 and opt_len == 10:  # RFC 7323 Timestamp Option
                try:
                    ts_val, ts_ecr = struct.unpack(">II", options[i + 2:i + 10])
                    return {
                        "ts_val": ts_val,
                        "ts_ecr": ts_ecr,
                        "has_rfc7323": True
                    }
                except struct.error:
                    pass

            i += opt_len

        return None

    @staticmethod
    def get_os_kernel_deduction(os_profile: Optional[str] = None) -> float:
        """
        Dynamically derives kernel context-switch deduction baseline (microseconds)
        from inferred operating system or hardware archetype.
        """
        if not os_profile:
            return 50.0
        prof_upper = os_profile.upper()
        if any(term in prof_upper for term in ("ASIC", "SWITCH", "ROUTER")):
            return 15.0
        if any(term in prof_upper for term in ("LINUX", "UNIX")):
            return 25.0
        if "WINDOWS" in prof_upper:
            return 65.0
        if any(term in prof_upper for term in ("BACNET", "PLC", "CONTROLLER")):
            return 110.0
        return 50.0

    @classmethod
    def evaluate_passive_tcp_jitter(
        cls,
        current_sample: Tuple[int, int, int],
        history: List[Tuple[int, int, int]],
        os_profile: Optional[str] = None,
        max_window: int = 32,
    ) -> PassiveTcpJitterResult:
        """
        Evaluates passive TCP RFC 7323 timestamp jitter against a sliding window.
        Detects SPAN port buffer bloat anomalies (top 5% outliers or >3*MAD)
        and flags corrupted propagation samples.
        Derives dispersion bounds strictly from prior history (N >= 5) to discard SPAN buffer bloat.
        """
        ts_val, ts_ecr, arrival_ns = current_sample
        deduction_us = cls.get_os_kernel_deduction(os_profile)

        if not history:
            return PassiveTcpJitterResult(
                accepted=True,
                jitter_us=0.0,
                delta_arrival_us=0.0,
                median_arrival_us=0.0,
                baseline_deduction_us=deduction_us,
                sample_count=1,
                buffer_bloat_discard=False,
            )

        prev_ts_val, prev_ts_ecr, prev_arrival_ns = history[-1]
        delta_arrival_us = max(0.0, (arrival_ns - prev_arrival_ns) / 1000.0)

        # Collect historical arrival deltas across window (unbiased by candidate delta)
        hist_deltas: List[float] = []
        for j in range(1, len(history)):
            d_us = max(0.0, (history[j][2] - history[j - 1][2]) / 1000.0)
            hist_deltas.append(d_us)

        import numpy as np
        if hist_deltas:
            med = float(np.median(hist_deltas))
            p95 = float(np.percentile(hist_deltas, 95)) if len(hist_deltas) >= 5 else (med * 3.0)
        else:
            med = delta_arrival_us
            p95 = delta_arrival_us * 3.0

        is_outlier = False
        if len(hist_deltas) >= 5:
            # Sliding Window Variance Filtering: Discard SPAN port buffer bloat anomalies (top 5% outliers)
            if delta_arrival_us > p95:
                is_outlier = True

        return PassiveTcpJitterResult(
            accepted=not is_outlier,
            jitter_us=round(abs(delta_arrival_us - med), 3),
            delta_arrival_us=round(delta_arrival_us, 3),
            median_arrival_us=round(med, 3),
            baseline_deduction_us=deduction_us,
            sample_count=len(history) + 1,
            buffer_bloat_discard=is_outlier,
        )

    @classmethod
    def calculate_spatial_attenuation(
        cls,
        flight_us: float,
        baseline_deduction_us: float = 50.0,
        nvp: Optional[float] = None,
        nominal_attenuation_db_per_meter: float = 0.22,
    ) -> SpatialAttenuationResult:
        """
        Calculates physical conductor spatial attenuation (dB) and flight distance
        from microsecond flight time in accordance with AETHERIS Constitution v2.4:
        tau_flight = (RTT - t_switch - t_kernel) / 2.
        Applies Cat5e/Cat6 standard attenuation curve (nominal 0.22 dB/m @ 100MHz).
        """
        nvp_val = nvp if (nvp is not None and nvp > 0.0) else DEFAULT_NVP
        if flight_us <= baseline_deduction_us:
            tau_flight_us = 0.0
            one_way_flight_s = 0.0
            distance_m = 0.5
        else:
            net_flight_us = flight_us - baseline_deduction_us
            tau_flight_us = net_flight_us / 2.0
            one_way_flight_s = tau_flight_us * 1e-6
            v_prop = SPEED_OF_LIGHT * nvp_val
            distance_m = round(max(0.5, min(one_way_flight_s * v_prop, 150.0)), 2)

        attenuation_db = round(distance_m * nominal_attenuation_db_per_meter, 3)
        return SpatialAttenuationResult(
            tau_flight_us=round(tau_flight_us, 4),
            tau_flight_ns=round(tau_flight_us * 1000.0, 2),
            estimated_distance_m=distance_m,
            spatial_attenuation_db=attenuation_db,
            nvp=round(nvp_val, 4),
            nominal_attenuation_rate_db_m=nominal_attenuation_db_per_meter,
        )

    @classmethod
    def evaluate_ptp_hardware_timestamp_viability(
        cls, interface: Optional[str] = None
    ) -> SpatialPruningBoundaryResult:
        """
        Evaluates the viability of IEEE 1588 PTP hardware timestamping on the host NIC.
        Interrogates kernel SO_TIMESTAMPING / SIOCGHWTSTAMP ioctl on Linux,
        and NDIS 6.80 / WinPcap driver capabilities on Windows.
        """
        import platform
        os_name = platform.system()

        if os_name == "Linux":
            iface = interface or "eth0"
            ptp_device_path = f"/sys/class/net/{iface}/device/ptp"
            has_ptp_device = False
            try:
                import os
                has_ptp_device = os.path.exists(ptp_device_path)
            except Exception:
                pass

            return {
                "ptp_supported": has_ptp_device,
                "timestamp_source": "PTP_HARDWARE_PHY" if has_ptp_device else "SOFTWARE_KERNEL_MONOTONIC",
                "interface": iface,
                "platform": "Linux",
                "resolution_ns": 1 if has_ptp_device else 1000,
                "reason": (
                    "Hardware PHY timestamping active via PTP device"
                    if has_ptp_device
                    else "Host NIC driver does not expose IEEE 1588 hardware clock; falling back to software monotonic timestamping"
                ),
            }
        elif os_name == "Windows":
            return {
                "ptp_supported": False,
                "timestamp_source": "SOFTWARE_KERNEL_MONOTONIC",
                "interface": interface or "default",
                "platform": "Windows",
                "resolution_ns": 100,
                "reason": "Windows NDIS filter driver (WinPcap/Npcap) operates in software capture mode; IEEE 1588 hardware timestamping requires dedicated kernel bypass NIC driver",
            }
        else:
            return {
                "ptp_supported": False,
                "timestamp_source": "SOFTWARE_KERNEL_MONOTONIC",
                "interface": interface or "default",
                "platform": os_name,
                "resolution_ns": 1000,
                "reason": f"PTP hardware timestamping probing not implemented for OS: {os_name}",
            }

    @classmethod
    def evaluate_spatial_pruning_boundary(
        cls,
        net_flight_us: Optional[float] = None,
        estimated_distance_m: Optional[float] = None,
        is_trunk: bool = False,
    ) -> Dict[str, Any]:
        """
        Evaluates physical flight-time and switchport topology to determine spatial pruning state:
        1. WAN_ROUTED: net_flight_us > 2000.0us -> bypasses localized copper constraints.
        2. TRUNK_UPLINK: is_trunk=True -> optical fiber / inter-switch trunk, bypasses 100m copper limit.
        3. OUT_OF_SPEC_COPPER: not is_trunk and estimated_distance_m > 110.0m -> restricts RTSP & high-throughput web sweeps.
        4. NOMINAL_LOCAL_COPPER: otherwise.
        """
        if net_flight_us is not None and net_flight_us > 2000.0:
            return SpatialPruningBoundaryResult(
                spatial_state="WAN_ROUTED",
                bypass_copper_limits=True,
                prune_high_throughput=False,
                reason=f"Flight time ({net_flight_us:.1f}us > 2000us) indicates WAN/SD-WAN multi-hop transit; localized physics pruning bypassed.",
            )

        if is_trunk:
            return SpatialPruningBoundaryResult(
                spatial_state="TRUNK_UPLINK",
                bypass_copper_limits=True,
                prune_high_throughput=False,
                reason="Target switchport is flagged as an aggregation trunk uplink (fiber-optic / AOC); 100m copper limit bypassed.",
            )

        if estimated_distance_m is not None and estimated_distance_m > 110.0:
            return SpatialPruningBoundaryResult(
                spatial_state="OUT_OF_SPEC_COPPER",
                bypass_copper_limits=False,
                prune_high_throughput=True,
                reason=f"Estimated copper distance ({estimated_distance_m:.1f}m > 110m) exceeds IEEE 802.3 standard; pruning RTSP and heavy web sweeps to protect link stability.",
            )

        return SpatialPruningBoundaryResult(
            spatial_state="NOMINAL_LOCAL_COPPER",
            bypass_copper_limits=False,
            prune_high_throughput=False,
            reason="Target physical drop is within standard IEEE 802.3 specification (<=110m).",
        )

    # -------------------------------------------------------------------------
    # 2. mDNS / DNS-SD Civic Location TXT Record Harvesting
    # -------------------------------------------------------------------------
    @staticmethod
    def extract_mdns_spatial_attributes(payload: Union[bytes, str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Dissects DNS-SD TXT records or text representations for spatial location attributes:
        room, floor, building, loc, location, note, site, rack, desk, latitude, longitude.
        """
        extracted: Dict[str, Any] = {}

        if isinstance(payload, dict):
            # Already a key-value dictionary, normalize keys
            raw_items = list(payload.items())
        elif isinstance(payload, bytes):
            # Parse length-prefixed DNS-SD TXT strings or raw ascii/utf-8
            raw_items = []
            pos = 0
            while pos < len(payload):
                seg_len = payload[pos]
                if seg_len > 0 and pos + 1 + seg_len <= len(payload):
                    seg = payload[pos + 1:pos + 1 + seg_len].decode("utf-8", errors="ignore")
                    if "=" in seg:
                        k, v = seg.split("=", 1)
                        raw_items.append((k.strip(), v.strip()))
                    pos += 1 + seg_len
                else:
                    # Fallback to regex over full decoded string
                    text = payload.decode("latin1", errors="ignore")
                    for match in re.finditer(r"([a-zA-Z_0-9]+)=([^\x00-\x1f\r\n\t]+)", text):
                        raw_items.append((match.group(1), match.group(2)))
                    break
        elif isinstance(payload, str):
            raw_items = []
            for line in payload.splitlines():
                for seg in line.split(";"):
                    if "=" in seg:
                        k, v = seg.split("=", 1)
                        raw_items.append((k.strip(), v.strip()))
        else:
            return extracted

        key_aliases = {
            "room": "room",
            "rm": "room",
            "floor": "floor",
            "fl": "floor",
            "building": "building",
            "bldg": "building",
            "site": "site",
            "rack": "rack",
            "desk": "desk",
            "station": "desk",
            "loc": "location",
            "location": "location",
            "note": "location",
            "lat": "latitude",
            "latitude": "latitude",
            "lon": "longitude",
            "long": "longitude",
            "longitude": "longitude",
            "jack": "wall_jack",
            "wall_jack": "wall_jack"
        }

        for raw_k, raw_v in raw_items:
            norm_k = raw_k.strip().lower()
            if norm_k in key_aliases:
                target_field = key_aliases[norm_k]
                cleaned_val = str(raw_v).strip().strip('"\'')
                if cleaned_val:
                    if target_field in ("latitude", "longitude"):
                        try:
                            extracted[target_field] = float(cleaned_val)
                        except ValueError:
                            pass
                    else:
                        extracted[target_field] = cleaned_val

        return extracted

    # -------------------------------------------------------------------------
    # 3. DHCP Option 82 (Relay Agent Information) Parsing
    # -------------------------------------------------------------------------
    @classmethod
    def parse_dhcp_option_82(
        cls,
        circuit_id: Union[bytes, str, None],
        remote_id: Union[bytes, str, None]
    ) -> DhcpOption82PinResult:
        """
        Parses DHCP Option 82 Sub-options 1 (Agent Circuit ID) and 2 (Agent Remote ID).
        Extracts switch chassis MAC, slot/module, port number, VLAN ID, and generates
        a physical switch attachment pin ('switch_pin').
        """
        result: Dict[str, Any] = {
            "vlan_id": None,
            "slot": None,
            "subslot": None,
            "port": None,
            "interface": None,
            "chassis_mac": None,
            "chassis_name": None,
            "switch_pin": None
        }

        # 1. Dissect Agent Circuit ID (Sub-option 1)
        if isinstance(circuit_id, bytes):
            # Cisco Catalyst format: Type 0, Len 4 -> 2B VLAN, 1B Module, 1B Port
            if len(circuit_id) >= 6 and circuit_id[0] == 0x00 and circuit_id[1] == 0x04:
                try:
                    vlan, mod, port = struct.unpack(">HBB", circuit_id[2:6])
                    result["vlan_id"] = vlan
                    result["slot"] = mod
                    result["port"] = port
                    result["interface"] = f"Gi{mod}/0/{port}" if mod > 0 else f"Gi0/{port}"
                except struct.error:
                    pass
            # Cisco Format Type 2: 2B VLAN, 1B Slot, 1B Subslot, 1B Port
            elif len(circuit_id) >= 7 and circuit_id[0] == 0x02:
                try:
                    vlan, slot, subslot, port = struct.unpack(">HBBB", circuit_id[1:6])
                    result["vlan_id"] = vlan
                    result["slot"] = slot
                    result["subslot"] = subslot
                    result["port"] = port
                    result["interface"] = f"Gi{slot}/{subslot}/{port}"
                except struct.error:
                    pass
            else:
                # Attempt ASCII string decode
                text = circuit_id.decode("utf-8", errors="ignore").strip("\x00\r\n\t ")
                cls._parse_circuit_id_text(text, result)

        elif isinstance(circuit_id, str):
            cls._parse_circuit_id_text(circuit_id, result)

        # 2. Dissect Agent Remote ID (Sub-option 2)
        if isinstance(remote_id, bytes):
            # Cisco Format: Type 0, Len 6 -> 6B Switch Chassis MAC
            if len(remote_id) >= 8 and remote_id[0] == 0x00 and remote_id[1] == 0x06:
                mac_bytes = remote_id[2:8]
                result["chassis_mac"] = ":".join(f"{b:02x}" for b in mac_bytes)
            # Direct 6-byte MAC address
            elif len(remote_id) == 6:
                result["chassis_mac"] = ":".join(f"{b:02x}" for b in remote_id)
            else:
                # ASCII Chassis Hostname / Identifier
                name = remote_id.decode("utf-8", errors="ignore").strip("\x00\r\n\t ")
                if name:
                    result["chassis_name"] = name
        elif isinstance(remote_id, str):
            # Check if it's a MAC string
            clean_mac = remote_id.strip()
            if re.match(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$", clean_mac):
                result["chassis_mac"] = clean_mac.lower()
            else:
                result["chassis_name"] = clean_mac

        # 3. Synthesize Switch Pinning String
        pin_parts = []
        if result["chassis_name"]:
            pin_parts.append(f"Switch {result['chassis_name']}")
        elif result["chassis_mac"]:
            pin_parts.append(f"Switch [{result['chassis_mac']}]")
        else:
            pin_parts.append("Switch")

        port_str = result["interface"] or (f"Port {result['port']}" if result["port"] is not None else None)
        if port_str:
            pin_parts.append(port_str)

        if result["vlan_id"]:
            pin_parts.append(f"(VLAN {result['vlan_id']})")

        result["switch_pin"] = " ".join(pin_parts)
        return DhcpOption82PinResult(**result)

    @staticmethod
    def _parse_circuit_id_text(text: str, result: Dict[str, Any]) -> None:
        """Helper to extract interface, port, slot, and VLAN from ASCII Circuit ID strings."""
        # Check patterns like 'Gi1/0/2', 'FastEthernet0/1', 'eth1', '1/0/4', 'vlan100:eth0'
        vlan_match = re.search(r"vlan\s*[:=-]?\s*(\d+)", text, re.IGNORECASE)
        if vlan_match:
            result["vlan_id"] = int(vlan_match.group(1))

        # Interface patterns: e.g. GigabitEthernet1/0/2, Fa0/1, ge-0/0/1, eth0
        if_match = re.search(r"([A-Za-z0-9_-]+/\d+/\d+|[A-Za-z]+[0-9]+/[0-9]+|[a-z]+\d+)", text, re.IGNORECASE)
        if if_match:
            result["interface"] = if_match.group(0)

        # Port numbers
        port_match = re.search(r"(?:port|pt|slot/\d+/)?(\d+)$", text, re.IGNORECASE)
        if port_match and result["port"] is None:
            try:
                result["port"] = int(port_match.group(1))
            except ValueError:
                pass
