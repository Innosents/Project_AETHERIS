"""
GraphPath Advanced Spatial Prober
Non-credentialed physical spatial interrogation vectors:
1. RFC 7323 TCP Timestamp Flight-Time & Microsecond Tick Jitter Calibration
2. mDNS / DNS-SD Civic Location TXT Record Harvesting
3. DHCP Option 82 (Agent Circuit ID / Remote ID) Switch-Port Pinning
"""

import socket
import struct
import time
import re
from typing import Dict, Any, Optional, List, Union
from loguru import logger

SPEED_OF_LIGHT = 299_792_458  # meters/sec
DEFAULT_NVP = 0.69             # Nominal Velocity of Propagation for Cat5e/Cat6 copper


class AdvancedSpatialProber:
    """
    Executes non-credentialed Layer 2/4 spatial interrogation to isolate
    physical media distance and exact switch port attachments.
    """

    # -------------------------------------------------------------------------
    # 1. Microsecond TCP Flight Time Calibration (RFC 7323)
    # -------------------------------------------------------------------------
    @staticmethod
    def calculate_flight_distance_from_us(
        flight_us: float,
        baseline_deduction_us: float = 50.0,
        nvp: float = DEFAULT_NVP,
        min_distance_m: float = 0.5,
        max_distance_m: float = 150.0
    ) -> Dict[str, Any]:
        """
        Calculates conductor length (meters) from measured microsecond flight time.
        Deducts nominal kernel TCP/IP context switch baseline (~50us for local LAN switch).
        Converts one-way propagation time into physical distance using copper NVP.
        """
        if flight_us <= baseline_deduction_us:
            net_flight_us = 0.0
            one_way_flight_s = 0.0
            clamped_distance = min_distance_m
        else:
            net_flight_us = flight_us - baseline_deduction_us
            one_way_flight_s = (net_flight_us * 1e-6) / 2.0
            v_prop = SPEED_OF_LIGHT * nvp
            raw_distance_m = one_way_flight_s * v_prop
            clamped_distance = round(max(min_distance_m, min(raw_distance_m, max_distance_m)), 2)

        # Confidence is highest when flight time is consistent and within standard Ethernet reach
        confidence = 0.85 if flight_us <= 200.0 else (0.75 if flight_us <= 1000.0 else 0.60)

        return {
            "raw_rtt_us": round(flight_us, 2),
            "baseline_deduction_us": baseline_deduction_us,
            "net_flight_us": round(net_flight_us, 3),
            "one_way_flight_ns": round(one_way_flight_s * 1e9, 2),
            "estimated_distance_meters": clamped_distance,
            "estimated_distance_feet": round(clamped_distance * 3.28084, 2),
            "confidence_score": confidence,
            "derivation_method": "MICROSECOND_TCP_FLIGHT_CALIBRATION"
        }

    @classmethod
    def measure_tcp_timestamp_flight(
        cls,
        ip: str,
        port: int,
        timeout: float = 0.4,
        samples: int = 3,
        baseline_deduction_us: float = 50.0
    ) -> Optional[Dict[str, Any]]:
        """
        Connects with TCP_NODELAY across open port, measuring microsecond flight times.
        Takes multiple samples to eliminate scheduling jitter outliers.
        """
        measurements: List[float] = []

        for _ in range(samples):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(timeout)
            try:
                t_start = time.perf_counter()
                sock.connect((ip, port))
                t_elapsed = (time.perf_counter() - t_start) * 1e6  # Microseconds
                measurements.append(t_elapsed)
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            finally:
                try:
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
        res["jitter_us"] = round(jitter_us, 2)
        res["sample_count"] = len(measurements)
        res["target_port"] = port
        return res

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
    ) -> Dict[str, Any]:
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
        return result

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
