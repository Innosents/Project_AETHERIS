"""
Project AETHERIS - Unit Tests for DHCP Option 55 Parameter Request List (PRL) Passive Stack Fingerprinter
Verifies:
  - Exact ordered PRL sequence matching (Windows 11, Apple Darwin, Linux, Axis Cam, HP Printer)
  - Option 60 Vendor Class Identifier corroboration and confidence weighting (95.0% -> 99.0%)
  - Robustness against malformed, truncated, and corrupted DHCP payloads
  - Clean background thread lifecycle and sub-second teardown
  - JSON symmetry and null terminator / control character sanitization
  - Direct persistence into spatial_ledger.db (inferred_os_profiles & device_registry)
  - Package exports from aetheris.core.fingerprinting
"""

import json
import socket
import sqlite3
import time
from pathlib import Path
from typing import Optional, List, Tuple

import pytest

from aetheris.core.fingerprinting import (
    DHCPPassiveListener,
    parse_dhcp_packet,
    match_dhcp_prl_fingerprint,
    DHCP_PRL_TAXONOMY
)


def build_mock_dhcp_packet(
    mac: str = "9C:54:DA:15:1E:7A",
    ciaddr: str = "0.0.0.0",
    requested_ip: Optional[str] = "192.168.1.73",
    prl: Optional[List[int]] = None,
    vendor_class: Optional[str] = None,
    hostname: Optional[str] = None,
    message_type: int = 3,  # 3 = DHCPREQUEST, 1 = DHCPDISCOVER
    corrupt_cookie: bool = False,
    extra_trailing_bytes: Optional[bytes] = None
) -> bytes:
    """
    Constructs a standards-compliant binary BOOTP/DHCP request frame.
    Header: 236 bytes
    Cookie: 4 bytes (0x63825363)
    Options: TLVs + 0xFF (End)
    """
    # Parse MAC
    clean_mac = mac.replace(":", "").replace("-", "")
    mac_bytes = bytes.fromhex(clean_mac)
    chaddr = mac_bytes + b"\x00" * (16 - len(mac_bytes))

    # IP addresses
    ciaddr_bytes = socket.inet_aton(ciaddr)
    yiaddr_bytes = b"\x00\x00\x00\x00"
    siaddr_bytes = b"\x00\x00\x00\x00"
    giaddr_bytes = b"\x00\x00\x00\x00"

    # BOOTP Header (236 bytes)
    header = bytearray(236)
    header[0] = 1  # op: BOOTREQUEST
    header[1] = 1  # htype: Ethernet (10Mb)
    header[2] = 6  # hlen: 6
    header[3] = 0  # hops: 0
    header[4:8] = b"\x12\x34\x56\x78"  # xid
    header[8:10] = b"\x00\x00"  # secs
    header[10:12] = b"\x80\x00"  # flags (broadcast)
    header[12:16] = ciaddr_bytes
    header[16:20] = yiaddr_bytes
    header[20:24] = siaddr_bytes
    header[24:28] = giaddr_bytes
    header[28:44] = chaddr
    # sname: 44:108 (64 bytes)
    # file: 108:236 (128 bytes)

    # Magic Cookie (4 bytes)
    if corrupt_cookie:
        cookie = b"\x00\x00\x00\x00"
    else:
        cookie = b"\x63\x82\x53\x63"

    # Options payload
    options = bytearray()

    # Option 53: DHCP Message Type
    options.extend([53, 1, message_type])

    # Option 50: Requested IP
    if requested_ip:
        req_ip_bytes = socket.inet_aton(requested_ip)
        options.extend([50, 4])
        options.extend(req_ip_bytes)

    # Option 55: Parameter Request List (PRL)
    if prl is not None:
        options.extend([55, len(prl)])
        options.extend(prl)

    # Option 60: Vendor Class Identifier
    if vendor_class is not None:
        vc_bytes = vendor_class.encode("latin-1") if isinstance(vendor_class, str) else bytes(vendor_class)
        options.extend([60, len(vc_bytes)])
        options.extend(vc_bytes)

    # Option 12: Client Hostname
    if hostname is not None:
        hn_bytes = hostname.encode("latin-1") if isinstance(hostname, str) else bytes(hostname)
        options.extend([12, len(hn_bytes)])
        options.extend(hn_bytes)

    # Option 255: End
    options.append(255)

    if extra_trailing_bytes:
        options.extend(extra_trailing_bytes)

    return bytes(header + cookie + options)


def test_parse_dhcp_option_55_windows_success():
    """Verifies Windows 11 PRL sequence parsing and Option 60 confidence boost."""
    windows_prl = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
    raw_packet = build_mock_dhcp_packet(
        mac="9C:54:DA:15:1E:7A",
        requested_ip="192.168.1.73",
        prl=windows_prl,
        vendor_class="MSFT 5.0",
        hostname="WIN11-WORKSTATION"
    )

    result = parse_dhcp_packet(raw_packet)
    assert result is not None
    assert result["mac"] == "9C:54:DA:15:1E:7A"
    assert result["ip"] == "192.168.1.73"
    assert result["os_profile"] == "WINDOWS_NT_10_11"
    assert result["confidence"] == 99.0  # Corroborated by Option 60 MSFT 5.0
    assert result["hostname"] == "WIN11-WORKSTATION"
    assert result["vendor"] == "Microsoft Corporation"
    assert result["device_type"] == "workstation"
    assert result["message_type"] == "DHCPREQUEST"
    assert result["prl_hash"] == "1,3,6,15,31,33,43,44,46,47,119,121,249,252"
    assert result["prl"] == windows_prl


def test_parse_dhcp_option_55_apple_darwin_success():
    """Verifies Apple iOS / macOS Darwin PRL sequence parsing."""
    apple_prl = [1, 121, 3, 6, 15, 114, 119, 252]
    raw_packet = build_mock_dhcp_packet(
        mac="BC:D0:74:11:22:33",
        requested_ip="192.168.1.80",
        prl=apple_prl,
        vendor_class="Apple iPhone",
        hostname="iPhone-15-Pro"
    )

    result = parse_dhcp_packet(raw_packet)
    assert result is not None
    assert result["mac"] == "BC:D0:74:11:22:33"
    assert result["ip"] == "192.168.1.80"
    assert result["os_profile"] == "APPLE_DARWIN_IOS_MACOS"
    assert result["confidence"] == 99.0  # Boosted by Apple Option 60
    assert result["vendor"] == "Apple Inc."
    assert result["device_type"] == "mobile_ios"
    assert result["hostname"] == "iPhone-15-Pro"


def test_parse_dhcp_linux_and_embedded_success():
    """Verifies Linux dhclient, systemd-networkd, Axis camera, and HP printer taxonomy."""
    # 1. Linux Standard dhclient
    linux_dhclient_prl = [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42]
    pkt_dhclient = build_mock_dhcp_packet(
        mac="00:15:5D:AA:BB:CC",
        prl=linux_dhclient_prl,
        vendor_class="isc-dhclient-4.4.1"
    )
    res_dhclient = parse_dhcp_packet(pkt_dhclient)
    assert res_dhclient is not None
    assert res_dhclient["os_profile"] == "LINUX_DHCLIENT_STANDARD"
    assert res_dhclient["confidence"] == 99.0

    # 2. Linux systemd-networkd (without corroborating vendor class -> 95.0% base)
    systemd_prl = [1, 3, 6, 12, 15, 26, 28, 42, 119, 121]
    pkt_systemd = build_mock_dhcp_packet(
        mac="52:54:00:12:34:56",
        prl=systemd_prl
    )
    res_systemd = parse_dhcp_packet(pkt_systemd)
    assert res_systemd is not None
    assert res_systemd["os_profile"] == "LINUX_SYSTEMD_NETWORKD"
    assert res_systemd["confidence"] == 95.0

    # 3. Axis Communications Camera
    axis_prl = [1, 3, 6, 12, 15, 28, 42, 43]
    pkt_axis = build_mock_dhcp_packet(
        mac="00:40:8C:11:22:33",
        prl=axis_prl,
        vendor_class="AXIS Communications Network Camera"
    )
    res_axis = parse_dhcp_packet(pkt_axis)
    assert res_axis is not None
    assert res_axis["os_profile"] == "EMBEDDED_AXIS_CAM"
    assert res_axis["confidence"] == 99.0

    # 4. HP Enterprise Printer
    hp_prl = [1, 3, 6, 15, 43]
    pkt_hp = build_mock_dhcp_packet(
        mac="00:1E:0B:44:55:66",
        prl=hp_prl,
        vendor_class="Hewlett-Packard JetDirect"
    )
    res_hp = parse_dhcp_packet(pkt_hp)
    assert res_hp is not None
    assert res_hp["os_profile"] == "EMBEDDED_PRINTER_HP"
    assert res_hp["confidence"] == 99.0


def test_malformed_and_truncated_dhcp_options():
    """Verifies defensive rejection and resilience against malformed buffers."""
    # 1. Truncated buffer (< 240 bytes)
    assert parse_dhcp_packet(b"\x01\x01\x06\x00" * 10) is None
    assert parse_dhcp_packet(b"") is None

    # 2. Corrupt DHCP Magic Cookie
    bad_cookie_packet = build_mock_dhcp_packet(corrupt_cookie=True)
    assert parse_dhcp_packet(bad_cookie_packet) is None

    # 3. Non-bytes types
    assert parse_dhcp_packet(None) is None  # type: ignore
    assert parse_dhcp_packet("invalid_string_buffer") is None  # type: ignore

    # 4. Truncated TLV option length (premature buffer end)
    valid_packet = build_mock_dhcp_packet(prl=[1, 3, 6])
    truncated_tlv_packet = valid_packet[:-3]  # Strip option bytes mid-TLV
    res = parse_dhcp_packet(truncated_tlv_packet)
    # Should either gracefully return partial parse or None without crashing
    if res is not None:
        assert isinstance(res, dict)

    # 5. Invalid opcode (op=99)
    bad_op_packet = bytearray(build_mock_dhcp_packet())
    bad_op_packet[0] = 99
    assert parse_dhcp_packet(bytes(bad_op_packet)) is None


def test_thread_worker_lifecycle_clean_teardown(tmp_path):
    """Verifies background thread worker spins up and cleanly shuts down in < 1.5s."""
    db_file = tmp_path / "test_lifecycle.db"
    listener = DHCPPassiveListener(db_path=str(db_file))

    listener.start_listener()
    assert listener._thread is not None
    assert listener._thread.is_alive()

    # Ingest a mock packet
    pkt = build_mock_dhcp_packet(
        mac="00:11:22:33:44:55",
        requested_ip="192.168.1.55",
        prl=[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
        vendor_class="MSFT 5.0"
    )
    parsed = listener.ingest_raw_packet(pkt)
    assert parsed is not None

    profiles = listener.get_discovered_profiles()
    assert "00:11:22:33:44:55" in profiles

    start_t = time.time()
    listener.stop_listener(timeout=1.5)
    duration = time.time() - start_t

    assert duration < 2.0
    assert listener._thread is None or not listener._thread.is_alive()


def test_json_symmetry_and_zero_bytes():
    """Verifies control character / null terminator sanitization and strict JSON serialization."""
    dirty_hostname = "WORKSTATION\x00\x00\x1b[31m\x07"
    dirty_vendor = "MSFT\x00PROD\x1f"

    pkt = build_mock_dhcp_packet(
        mac="AA:BB:CC:DD:EE:FF",
        requested_ip="192.168.1.99",
        prl=[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
        vendor_class=dirty_vendor,
        hostname=dirty_hostname
    )

    result = parse_dhcp_packet(pkt)
    assert result is not None

    # Null bytes and control characters must be purged
    assert "\x00" not in result["hostname"]
    assert "\x00" not in result["vendor_class_id"]
    assert "\x1f" not in result["vendor_class_id"]

    # Must serialize to JSON with 100% round-trip symmetry
    serialized = json.dumps(result)
    deserialized = json.loads(serialized)
    assert deserialized == result


def test_save_to_ledger(tmp_path):
    """Verifies persistence of discovered profiles into spatial_ledger.db."""
    db_file = tmp_path / "test_spatial_ledger.db"
    listener = DHCPPassiveListener(db_path=str(db_file))

    pkt_win = build_mock_dhcp_packet(
        mac="11:22:33:44:55:66",
        requested_ip="192.168.1.101",
        prl=[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
        vendor_class="MSFT 5.0",
        hostname="WIN-OFFICE"
    )
    listener.ingest_raw_packet(pkt_win)

    # Check database contents
    with sqlite3.connect(str(db_file)) as conn:
        row = conn.execute("SELECT ip, mac, os_profile, confidence FROM inferred_os_profiles WHERE mac = '11:22:33:44:55:66'").fetchone()
        assert row is not None
        assert row[0] == "192.168.1.101"
        assert row[1] == "11:22:33:44:55:66"
        assert row[2] == "WINDOWS_NT_10_11"
        assert row[3] == 99.0

        reg_row = conn.execute("SELECT mac_address, canonical_name, interface_tier FROM device_registry WHERE mac_address = '11:22:33:44:55:66'").fetchone()
        assert reg_row is not None
        assert reg_row[0] == "11:22:33:44:55:66"
        assert reg_row[1] == "WIN-OFFICE"
        assert reg_row[2] == "DHCP_PASSIVE"


def test_package_exports():
    """Verifies that all required symbols are cleanly exported from aetheris.core.fingerprinting."""
    import aetheris.core.fingerprinting as fp
    assert hasattr(fp, "DHCPPassiveListener")
    assert hasattr(fp, "parse_dhcp_packet")
    assert hasattr(fp, "match_dhcp_prl_fingerprint")
    assert hasattr(fp, "DHCP_PRL_TAXONOMY")
