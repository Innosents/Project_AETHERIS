"""
Project AETHERIS - DHCP Option 55 Parameter Request List (PRL) Passive Stack Fingerprinter
100% passive, zero-packet OS kernel and firmware fingerprinting engine.

Intercepts raw DHCP DISCOVER and REQUEST broadcast traffic (UDP ports 67/68),
extracts Option 55 (PRL), Option 60 (Vendor Class Identifier), and Option 12 (Client Hostname),
evaluates exact ordered sequence invariance against an authoritative taxonomy,
and streams inferred OS profiles directly into spatial_ledger.db with zero active network transmission.
"""

import os
import sys
import time
import socket
import sqlite3
import threading
import queue
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union

from graphpath.core.probers.sanitization import sanitize_prober_payload, clean_ascii_string

# ---------------------------------------------------------------------------
# Authoritative DHCP Option 55 (PRL) Fingerprint Taxonomy
# Exact ordered sequence tuples derived from OS network stack compile-time defaults
# ---------------------------------------------------------------------------

DHCP_PRL_TAXONOMY: Dict[Tuple[int, ...], Dict[str, Any]] = {
    # Modern Microsoft Windows (Windows 10 / Windows 11)
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252): {
        "os_profile": "WINDOWS_NT_10_11",
        "vendor": "Microsoft Corporation",
        "device_type": "workstation",
        "model": "Windows 10/11 Workstation Host",
        "expected_vendor_substr": ["msft", "microsoft"]
    },
    # Windows 11 Variant (without Option 119 Domain Search)
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249, 252): {
        "os_profile": "WINDOWS_NT_10_11",
        "vendor": "Microsoft Corporation",
        "device_type": "workstation",
        "model": "Windows 11 Workstation / Laptop",
        "expected_vendor_substr": ["msft", "microsoft"]
    },
    # Apple Darwin (iOS 15-18 & macOS)
    (1, 121, 3, 6, 15, 114, 119, 252): {
        "os_profile": "APPLE_DARWIN_IOS_MACOS",
        "vendor": "Apple Inc.",
        "device_type": "mobile_ios",
        "model": "Apple iOS / macOS Darwin Device",
        "expected_vendor_substr": ["apple", "darwin", "ios", "mac"]
    },
    # Apple iOS / iPadOS Mobile Variant
    (1, 121, 3, 6, 15, 119, 252): {
        "os_profile": "APPLE_DARWIN_IOS_MACOS",
        "vendor": "Apple Inc.",
        "device_type": "mobile_ios",
        "model": "Apple iPhone / iPad",
        "expected_vendor_substr": ["apple", "darwin", "ios", "mac"]
    },
    # Apple macOS Laptop Variant
    (1, 121, 3, 6, 15, 119, 252, 95, 44, 46): {
        "os_profile": "APPLE_DARWIN_IOS_MACOS",
        "vendor": "Apple Inc.",
        "device_type": "laptop",
        "model": "Apple MacBook (macOS)",
        "expected_vendor_substr": ["apple", "darwin", "ios", "mac"]
    },
    # Linux Standard dhclient
    (1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42): {
        "os_profile": "LINUX_DHCLIENT_STANDARD",
        "vendor": "Linux Foundation",
        "device_type": "workstation_or_server",
        "model": "Linux Standard dhclient",
        "expected_vendor_substr": ["linux", "dhclient", "isc"]
    },
    # Linux systemd-networkd
    (1, 3, 6, 12, 15, 26, 28, 42, 119, 121): {
        "os_profile": "LINUX_SYSTEMD_NETWORKD",
        "vendor": "Linux Foundation",
        "device_type": "server",
        "model": "Linux systemd-networkd",
        "expected_vendor_substr": ["systemd", "linux"]
    },
    # Axis Communications Network Surveillance Camera
    (1, 3, 6, 12, 15, 28, 42, 43): {
        "os_profile": "EMBEDDED_AXIS_CAM",
        "vendor": "Axis Communications",
        "device_type": "security_camera",
        "model": "Axis Network Camera / Surveillance Device",
        "expected_vendor_substr": ["axis"]
    },
    # HP JetDirect / Enterprise Network Printer
    (1, 3, 6, 15, 43): {
        "os_profile": "EMBEDDED_PRINTER_HP",
        "vendor": "HP Inc.",
        "device_type": "printer",
        "model": "HP JetDirect / Enterprise Network Printer",
        "expected_vendor_substr": ["hp", "hewlett", "jetdirect"]
    },
    # Embedded Linux IPTV Set-Top Box (ARRIS / Sagemcom / Technicolor)
    (1, 3, 6, 12, 15, 28, 42, 43, 66, 67, 121): {
        "os_profile": "EMBEDDED_LINUX_STB",
        "vendor": "ARRIS / CommScope",
        "device_type": "stb",
        "model": "IPTV Set-Top Box",
        "expected_vendor_substr": ["arris", "technicolor", "sagemcom", "humax", "tivo"]
    },
    # Samsung Tizen Smart TV
    (1, 3, 6, 15, 28, 33, 43, 119, 121, 252): {
        "os_profile": "TIZEN_OS",
        "vendor": "Samsung Electronics",
        "device_type": "smart_tv",
        "model": "Samsung Tizen Smart TV",
        "expected_vendor_substr": ["samsung", "tizen"]
    },
    # Android Wi-Fi Bridge / Extender
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 43): {
        "os_profile": "ANDROID_WLAN_BRIDGE",
        "vendor": "Google LLC / Bilian",
        "device_type": "wlan_bridge",
        "model": "Android / Wi-Fi Bridge Extender",
        "expected_vendor_substr": ["android", "bridge", "bilian", "extender"]
    },
}

# DHCP Message Types (Option 53)
DHCP_MESSAGE_TYPES = {
    1: "DHCPDISCOVER",
    2: "DHCPOFFER",
    3: "DHCPREQUEST",
    4: "DHCPDECLINE",
    5: "DHCPACK",
    6: "DHCPNAK",
    7: "DHCPRELEASE",
    8: "DHCPINFORM"
}


def match_dhcp_prl_fingerprint(
    prl: Union[Tuple[int, ...], List[int]],
    vendor_class: Optional[str] = None
) -> Dict[str, Any]:
    """
    Matches an ordered Parameter Request List (Option 55) against the authoritative taxonomy.
    Enforces ordered array sequence invariance.
    Confidence weighting:
      - 95.0% base confidence for exact ordered sequence match.
      - Boosts to 99.0% when Option 60 (Vendor Class Identifier) corroborates the stack.
      - Graceful heuristics fallback when PRL is unknown.
    """
    prl_tuple = tuple(int(x) for x in prl)
    vc = (vendor_class or "").lower().strip()
    prl_hash = ",".join(str(x) for x in prl_tuple) if prl_tuple else ""

    # Exact ordered sequence lookup
    if prl_tuple in DHCP_PRL_TAXONOMY:
        entry = DHCP_PRL_TAXONOMY[prl_tuple]
        expected_subs = entry.get("expected_vendor_substr", [])
        corroborated = bool(vc and any(sub in vc for sub in expected_subs))

        confidence = 99.0 if corroborated else 95.0
        evidence = (
            f"DHCP Option 55 exact PRL match: {entry['os_profile']} "
            f"[Corroborated by Option 60: '{vendor_class}']"
            if corroborated else
            f"DHCP Option 55 exact PRL match: {entry['os_profile']} (PRL={prl_hash})"
        )

        return {
            "os_profile": entry["os_profile"],
            "confidence": confidence,
            "evidence": evidence,
            "vendor": entry["vendor"],
            "device_type": entry["device_type"],
            "model": entry["model"],
            "matched_rule": "exact_prl_sequence_match",
            "prl_tuple": list(prl_tuple),
            "prl_hash": prl_hash
        }

    # Fallback Option 60 heuristic lookup when PRL sequence is uncataloged
    fallback_profile = "GENERIC_DHCP_CLIENT"
    fallback_vendor = "Unknown Vendor"
    fallback_type = "unknown"
    fallback_model = "Generic DHCP Endpoint"
    confidence = 50.0

    if vc:
        if any(w in vc for w in ("msft", "microsoft", "windows")):
            fallback_profile = "WINDOWS_NT_10_11"
            fallback_vendor = "Microsoft Corporation"
            fallback_type = "workstation"
            fallback_model = "Windows Host"
            confidence = 85.0
        elif any(w in vc for w in ("apple", "darwin", "ios", "mac")):
            fallback_profile = "APPLE_DARWIN_IOS_MACOS"
            fallback_vendor = "Apple Inc."
            fallback_type = "mobile_ios"
            fallback_model = "Apple iOS / macOS Host"
            confidence = 85.0
        elif "axis" in vc:
            fallback_profile = "EMBEDDED_AXIS_CAM"
            fallback_vendor = "Axis Communications"
            fallback_type = "security_camera"
            fallback_model = "Axis Network Camera"
            confidence = 85.0
        elif any(w in vc for w in ("hp", "hewlett", "jetdirect")):
            fallback_profile = "EMBEDDED_PRINTER_HP"
            fallback_vendor = "HP Inc."
            fallback_type = "printer"
            fallback_model = "HP Network Printer"
            confidence = 85.0
        elif "systemd" in vc:
            fallback_profile = "LINUX_SYSTEMD_NETWORKD"
            fallback_vendor = "Linux Foundation"
            fallback_type = "server"
            fallback_model = "Linux Endpoint (systemd-networkd)"
            confidence = 80.0
        elif any(w in vc for w in ("dhclient", "linux", "isc")):
            fallback_profile = "LINUX_DHCLIENT_STANDARD"
            fallback_vendor = "Linux Foundation"
            fallback_type = "workstation_or_server"
            fallback_model = "Linux Endpoint (dhclient)"
            confidence = 80.0
        elif any(w in vc for w in ("arris", "technicolor", "sagemcom", "humax", "tivo")):
            fallback_profile = "EMBEDDED_LINUX_STB"
            fallback_vendor = "ARRIS / CommScope"
            fallback_type = "stb"
            fallback_model = "IPTV STB"
            confidence = 80.0
        elif any(w in vc for w in ("samsung", "tizen")):
            fallback_profile = "TIZEN_OS"
            fallback_vendor = "Samsung Electronics"
            fallback_type = "smart_tv"
            fallback_model = "Samsung Smart TV"
            confidence = 80.0
        elif any(w in vc for w in ("android", "bilian", "bridge")):
            fallback_profile = "ANDROID_WLAN_BRIDGE"
            fallback_vendor = "Google LLC / Bilian"
            fallback_type = "wlan_bridge"
            fallback_model = "Wi-Fi Bridge / Android Endpoint"
            confidence = 80.0

    return {
        "os_profile": fallback_profile,
        "confidence": confidence,
        "evidence": f"Option 60 Vendor Fallback: '{vendor_class}' (Uncataloged PRL={prl_hash})",
        "vendor": fallback_vendor,
        "device_type": fallback_type,
        "model": fallback_model,
        "matched_rule": "vendor_class_fallback" if vc else "generic_unknown",
        "prl_tuple": list(prl_tuple),
        "prl_hash": prl_hash
    }


def parse_dhcp_packet(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Defensively parses raw BOOTP/DHCP bytes into structured, sanitized metadata.
    
    1. Validates BOOTP header minimum length (>= 240 bytes) and DHCP Magic Cookie (0x63825363).
    2. Supports both raw UDP payload frames and encapsulated IP/UDP packets.
    3. Extracts BOOTP header fields: Opcode, Hardware Type, Hardware Address (MAC), ciaddr.
    4. Iterates dynamic TLV options: Type 53 (Message Type), Type 55 (PRL), Type 60 (Vendor Class ID),
       Type 12 (Client Hostname), Type 50 (Requested IP).
    5. Matches ordered PRL sequence tuple against taxonomy with confidence weighting.
    6. Routes result through sanitize_prober_payload to guarantee strict JSON compliance.
    """
    if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
        return None

    raw = bytes(raw_bytes)
    magic = b"\x63\x82\x53\x63"
    magic_idx = raw.find(magic)

    # Magic cookie must be present and preceded by at least 236 bytes of BOOTP header
    if magic_idx == -1 or magic_idx < 236:
        return None

    bootp_start = magic_idx - 236
    bootp_data = raw[bootp_start:]
    if len(bootp_data) < 240:
        return None

    op = bootp_data[0]
    htype = bootp_data[1]
    hlen = bootp_data[2]
    
    # BOOTP operations: 1 = BOOTREQUEST, 2 = BOOTREPLY
    if op not in (1, 2):
        return None

    # Format Client Hardware Address (chaddr)
    mac_len = hlen if (0 < hlen <= 16) else 6
    chaddr_raw = bootp_data[28:28 + mac_len]
    mac = ":".join(f"{b:02X}" for b in chaddr_raw[:6]) if len(chaddr_raw) >= 6 else "00:00:00:00:00:00"

    try:
        ciaddr = socket.inet_ntoa(bootp_data[12:16])
    except Exception:
        ciaddr = "0.0.0.0"

    # Iterate Dynamic TLV Options starting from offset 240
    offset = 240
    total_len = len(bootp_data)
    
    message_type_id: Optional[int] = None
    message_type_str: str = ""
    prl_tuple: Tuple[int, ...] = ()
    vendor_class_id: str = ""
    hostname: str = ""
    requested_ip: str = ""

    while offset < total_len:
        opt_code = bootp_data[offset]
        if opt_code == 0:  # PAD
            offset += 1
            continue
        if opt_code == 255:  # END
            break

        # Defensive bounds check for TLV length byte
        if offset + 1 >= total_len:
            break

        opt_len = bootp_data[offset + 1]
        val_start = offset + 2
        val_end = val_start + opt_len

        # Defensive bounds check for truncated option value
        if val_end > total_len:
            break

        opt_val = bootp_data[val_start:val_end]
        offset = val_end

        if opt_code == 53:  # DHCP Message Type
            if len(opt_val) >= 1:
                message_type_id = int(opt_val[0])
                message_type_str = DHCP_MESSAGE_TYPES.get(message_type_id, f"DHCP_TYPE_{message_type_id}")
        elif opt_code == 55:  # Parameter Request List
            prl_tuple = tuple(int(b) for b in opt_val)
        elif opt_code == 60:  # Vendor Class Identifier
            vendor_class_id = clean_ascii_string(opt_val.decode(errors="replace"))
        elif opt_code == 12:  # Client Hostname
            hostname = clean_ascii_string(opt_val.decode(errors="replace"))
        elif opt_code == 50:  # Requested IP Address
            if len(opt_val) == 4:
                try:
                    requested_ip = socket.inet_ntoa(opt_val)
                except Exception:
                    pass

    # Resolve Effective IP (Requested IP > ciaddr > 0.0.0.0)
    effective_ip = requested_ip if (requested_ip and requested_ip != "0.0.0.0") else (
        ciaddr if (ciaddr and ciaddr != "0.0.0.0") else "0.0.0.0"
    )

    # Match PRL against authoritative taxonomy
    match_result = match_dhcp_prl_fingerprint(prl_tuple, vendor_class=vendor_class_id)
    prl_hash = ",".join(str(b) for b in prl_tuple) if prl_tuple else ""

    result = {
        "mac": mac,
        "ip": effective_ip,
        "message_type": message_type_str,
        "message_type_id": message_type_id,
        "prl": list(prl_tuple),
        "prl_tuple": list(prl_tuple),
        "prl_hash": prl_hash,
        "vendor_class_id": vendor_class_id,
        "hostname": hostname,
        "os_profile": match_result["os_profile"],
        "confidence": match_result["confidence"],
        "evidence": match_result["evidence"],
        "vendor": match_result.get("vendor", ""),
        "device_type": match_result.get("device_type", ""),
        "model": match_result.get("model", ""),
        "discovery_method": "passive_dhcp_prl_fingerprint",
        "timestamp": time.time()
    }

    return sanitize_prober_payload(result)


class DHCPPassiveListener:
    """
    Autonomous background worker thread that passively listens for DHCP broadcast frames.
    
    Architectural resilience:
      - Privilege Fallback: Gracefully attempts standard UDP socket binding (0.0.0.0:68 / 67)
        with SO_REUSEADDR and SO_BROADCAST, or Scapy background sniffer worker, without crashing.
      - Ephemeral Lifecycles: Daemon thread with bounded queue and threading.Event for sub-second
        clean teardown. Never blocks caller execution.
      - Ledger Integration: Streams discovered profiles directly into spatial_ledger.db.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        bounded_queue_size: int = 1000
    ) -> None:
        if db_path:
            self.db_path = Path(db_path)
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.db_path = base_dir / "spatial_ledger.db"

        self.bounded_queue_size = bounded_queue_size
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._discovered_profiles: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._socket: Optional[socket.socket] = None
        self.interface: Optional[str] = None
        self._init_db()

    def _init_db(self) -> None:
        """Ensures ledger tables exist in spatial_ledger.db."""
        if not self.db_path:
            return
        try:
            with sqlite3.connect(str(self.db_path), timeout=5.0) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS inferred_os_profiles (
                        ip TEXT PRIMARY KEY,
                        mac TEXT,
                        os_profile TEXT,
                        confidence REAL,
                        tcp_synack_ttl INTEGER,
                        tcp_window_size INTEGER,
                        dhcp_option55 TEXT,
                        evidence TEXT,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS device_registry (
                        mac_address TEXT PRIMARY KEY,
                        canonical_name TEXT NOT NULL,
                        interface_tier TEXT NOT NULL,
                        ground_truth_m REAL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except Exception:
            pass

    def start_listener(self, interface: Optional[str] = None) -> None:
        """Starts the unblocking background listener thread."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self.interface = interface
            self._thread = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name="DHCPPassiveListenerWorker"
            )
            self._thread.start()

    def stop_listener(self, timeout: float = 1.5) -> None:
        """Signals worker termination and cleanly joins the background thread."""
        self._stop_event.set()
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None

    def ingest_raw_packet(self, raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """
        Ingests and processes raw packet bytes.
        Updates discovered profiles cache and persists to spatial_ledger.db.
        """
        parsed = parse_dhcp_packet(raw_bytes)
        if not parsed:
            return None

        mac = parsed.get("mac", "00:00:00:00:00:00")
        with self._lock:
            self._discovered_profiles[mac] = parsed

        self._persist_profile(parsed)
        return parsed

    def get_discovered_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Returns a snapshot dictionary of all passively discovered profiles keyed by MAC."""
        with self._lock:
            return dict(self._discovered_profiles)

    def save_to_ledger(self, profiles: Optional[Dict[str, Dict[str, Any]]] = None) -> int:
        """Persists a batch of discovered profiles directly into spatial_ledger.db."""
        targets = profiles if profiles is not None else self.get_discovered_profiles()
        saved = 0
        for p in targets.values():
            self._persist_profile(p)
            saved += 1
        return saved

    def _persist_profile(self, parsed: Dict[str, Any]) -> None:
        """Persists an individual profile to spatial_ledger.db with conflict avoidance."""
        if not self.db_path:
            return
        try:
            ip = parsed.get("ip") or ""
            mac = parsed.get("mac") or ""
            os_profile = parsed.get("os_profile") or "GENERIC_DHCP_CLIENT"
            confidence = float(parsed.get("confidence", 95.0))
            opt55_str = parsed.get("prl_hash") or ""
            evidence = parsed.get("evidence") or ""
            hostname = parsed.get("hostname") or ""

            with sqlite3.connect(str(self.db_path), timeout=5.0) as conn:
                # Primary key resolution for inferred_os_profiles
                effective_ip = ip
                if not effective_ip or effective_ip == "0.0.0.0":
                    cursor = conn.execute(
                        "SELECT ip FROM inferred_os_profiles WHERE mac = ? AND ip != '0.0.0.0' LIMIT 1",
                        (mac,)
                    )
                    row = cursor.fetchone()
                    if row and row[0]:
                        effective_ip = row[0]
                    else:
                        effective_ip = f"dhcp-{mac}"

                conn.execute("""
                    INSERT OR REPLACE INTO inferred_os_profiles (
                        ip, mac, os_profile, confidence,
                        tcp_synack_ttl, tcp_window_size,
                        dhcp_option55, evidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    effective_ip, mac, os_profile, confidence,
                    None, None, opt55_str, evidence
                ))

                # Update device_registry
                canonical_name = hostname or f"{os_profile} ({mac})"
                conn.execute("""
                    INSERT OR IGNORE INTO device_registry (
                        mac_address, canonical_name, interface_tier, ground_truth_m
                    ) VALUES (?, ?, 'DHCP_PASSIVE', NULL)
                """, (mac, canonical_name))
                conn.commit()
        except Exception:
            pass

    def _worker_loop(self) -> None:
        """
        Background listener worker executing tiered fallback:
        Tier 1: Standard UDP socket bound to 0.0.0.0:68 or 0.0.0.0:67
        Tier 2: Scapy background sniffer if available
        Tier 3: Graceful sleep waiting on stop event
        """
        # Tier 1: Attempt standard UDP socket binding
        bound_sock: Optional[socket.socket] = None
        for port in (68, 67):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_BROADCAST"):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(0.5)
                s.bind(("0.0.0.0", port))
                bound_sock = s
                break
            except Exception:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

        if bound_sock:
            self._socket = bound_sock
            try:
                while not self._stop_event.is_set():
                    try:
                        data, addr = bound_sock.recvfrom(4096)
                        if data:
                            self.ingest_raw_packet(data)
                    except socket.timeout:
                        continue
                    except Exception:
                        break
            finally:
                try:
                    bound_sock.close()
                except Exception:
                    pass
                self._socket = None
            return

        # Tier 2: Attempt Scapy background sniffer if framework is present
        try:
            from scapy.all import sniff
            while not self._stop_event.is_set():
                try:
                    sniff(
                        filter="udp and (port 67 or port 68)",
                        prn=lambda pkt: self._handle_scapy_packet(pkt),
                        iface=self.interface,
                        store=False,
                        timeout=0.5,
                        stop_filter=lambda p: self._stop_event.is_set()
                    )
                except Exception:
                    break
        except Exception:
            pass

        # Tier 3: Passive idle wait if interface acquisition is blocked
        while not self._stop_event.is_set():
            self._stop_event.wait(0.5)

    def _handle_scapy_packet(self, pkt: Any) -> None:
        """Handles Scapy-captured frames and routes raw bytes to ingest_raw_packet."""
        try:
            raw_bytes = bytes(pkt)
            self.ingest_raw_packet(raw_bytes)
        except Exception:
            pass
