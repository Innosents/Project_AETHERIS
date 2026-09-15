"""
Project AETHERIS - Unit Test Suite for Passive Enterprise DPI Decoders (Ingestion 4)
Verifies:
1. Ubiquiti UBNT Discovery Decoder (USW switch vs U6-Pro AP archetypes, t_kernel priors)
2. MikroTik MNDP Decoder (CRS switch vs CCR router archetypes, t_kernel priors)
3. BACnet/IP Decoder (I-Am device instance ID extraction, Who-Is workstation query distinction)
4. STP/RSTP/MSTP BPDU Decoder (Root Bridge MAC, Path Cost, is_root_bridge, LLC stripping)
5. DpiDispatcher multi-port and heuristic routing
6. Truncation, zero-length, and corruption resilience
7. Strict JSON round-trip invariance and sanitize_prober_payload compliance
8. TelemetryLedger stp_topology_ledger persistence
"""

import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from graphpath.core.fingerprinting.dpi_decoders import (
    UbntDiscoveryDecoder,
    MikrotikMndpDecoder,
    BacnetIpDecoder,
    StpBpduDecoder,
    DpiDispatcher,
    KERNEL_PRIOR_ASIC_SWITCH_MEAN_US,
    KERNEL_PRIOR_ROUTER_AP_MEAN_US,
    KERNEL_PRIOR_BACNET_CTRL_MEAN_US,
)
from graphpath.core.fingerprinting.dpi_normalizers import (
    robust_z_score,
    normalize_stp_path_cost,
    TelemetryAnomalyFilter,
    BayesianTurnaround,
)
from graphpath.core.telemetry_ledger import TelemetryLedger


def build_ubnt_payload(
    version: int = 1,
    mac: bytes = b"\x74\x83\xC2\x11\x22\x33",
    firmware: str = "6.5.32.14505",
    hostname: str = "Core-USW-24-PoE",
    model: str = "USW-24-PoE",
) -> bytes:
    """Builds a synthetic Ubiquiti Discovery Protocol (UBNT) packet."""
    tlvs = bytearray()

    # TLV 0x01: MAC Address (6 bytes)
    if mac:
        tlvs.append(0x01)
        tlvs.extend(struct.pack(">H", len(mac)))
        tlvs.extend(mac)

    # TLV 0x03: Firmware
    if firmware:
        fw_b = firmware.encode("utf-8")
        tlvs.append(0x03)
        tlvs.extend(struct.pack(">H", len(fw_b)))
        tlvs.extend(fw_b)

    # TLV 0x0B: Hostname
    if hostname:
        host_b = hostname.encode("utf-8")
        tlvs.append(0x0B)
        tlvs.extend(struct.pack(">H", len(host_b)))
        tlvs.extend(host_b)

    # TLV 0x0C: Model
    if model:
        mod_b = model.encode("utf-8")
        tlvs.append(0x0C)
        tlvs.extend(struct.pack(">H", len(mod_b)))
        tlvs.extend(mod_b)

    header = struct.pack(">BBH", version, 0x00, len(tlvs))
    return bytes(header + tlvs)


def build_mndp_payload(
    mac: bytes = b"\x48\x8F\x5A\x12\x34\x56",
    identity: str = "Switch-CRS328-24P",
    version: str = "7.14.3",
    board: str = "CRS328-24P-4S+RM",
    arch: str = "arm",
) -> bytes:
    """Builds a synthetic MikroTik Neighbor Discovery Protocol (MNDP) packet."""
    tlvs = bytearray()

    # TLV 0x01: MAC (6 bytes)
    if mac:
        tlvs.extend(struct.pack(">HH", 0x01, len(mac)))
        tlvs.extend(mac)

    # TLV 0x05: Identity / Hostname
    if identity:
        id_b = identity.encode("utf-8")
        tlvs.extend(struct.pack(">HH", 0x05, len(id_b)))
        tlvs.extend(id_b)

    # TLV 0x07: Software Version
    if version:
        ver_b = version.encode("utf-8")
        tlvs.extend(struct.pack(">HH", 0x07, len(ver_b)))
        tlvs.extend(ver_b)

    # TLV 0x08: Board / Platform
    if board:
        board_b = board.encode("utf-8")
        tlvs.extend(struct.pack(">HH", 0x08, len(board_b)))
        tlvs.extend(board_b)

    # TLV 0x0A: Architecture
    if arch:
        arch_b = arch.encode("utf-8")
        tlvs.extend(struct.pack(">HH", 0x0A, len(arch_b)))
        tlvs.extend(arch_b)

    return bytes(tlvs)


def build_bacnet_iam_payload(device_instance: int = 12345) -> bytes:
    """Builds a synthetic BACnet/IP I-Am broadcast announcement frame."""
    # BVLC: Type 0x81, Func 0x0A (Original-Unicast-NPDU), Length (to be calculated)
    npdu = b"\x01\x00"  # Version 1, Control 0 (no DNET/SNET routing)
    # APDU: Type 1 (Unconfirmed-Request, 0x10), Service 0x00 (I-Am)
    apdu_header = b"\x10\x00"
    # Object Identifier tag 12 (0xC4) + 4 bytes Object Identifier (Object Type 8 = Device, Instance ID)
    raw_obj_id = (8 << 22) | (device_instance & 0x3FFFFF)
    iam_body = b"\xC4" + struct.pack(">I", raw_obj_id) + b"\x22\x04\x00\x91\x03\x21\x01"

    apdu = apdu_header + iam_body
    total_len = 4 + len(npdu) + len(apdu)
    bvlc = struct.pack(">BBH", 0x81, 0x0A, total_len)
    return bvlc + npdu + apdu


def build_bacnet_routed_iam_payload(
    device_instance: int = 1234, snet: int = 1001, sadr: bytes = b"\x05"
) -> bytes:
    """Builds a synthetic BACnet/IP I-Am packet routed through an MS/TP router (SNET bit set)."""
    # NPDU: Version 1, Control 0x08 (Bit 3 = SNET present)
    npdu = bytearray([0x01, 0x08])
    npdu.extend(struct.pack(">HB", snet, len(sadr)))
    npdu.extend(sadr)

    # APDU: Type 1 (Unconfirmed-Request, 0x10), Service 0x00 (I-Am)
    apdu_header = b"\x10\x00"
    raw_obj_id = (8 << 22) | (device_instance & 0x3FFFFF)
    iam_body = b"\xC4" + struct.pack(">I", raw_obj_id) + b"\x22\x04\x00\x91\x03\x21\x01"
    apdu = apdu_header + iam_body
    total_len = 4 + len(npdu) + len(apdu)
    bvlc = struct.pack(">BBH", 0x81, 0x0A, total_len)
    return bvlc + bytes(npdu) + apdu


def build_bacnet_whois_payload() -> bytes:
    """Builds a synthetic BACnet/IP Who-Is broadcast discovery frame from a client workstation."""
    # BVLC: Type 0x81, Func 0x0B (Original-Broadcast-NPDU)
    npdu = b"\x01\x20\xFF\xFF\x00\xFF"  # Version 1, Control 0x20 (DNET broadcast)
    apdu = b"\x10\x08"  # Unconfirmed-Request, Service 0x08 (Who-Is)
    total_len = 4 + len(npdu) + len(apdu)
    bvlc = struct.pack(">BBH", 0x81, 0x0B, total_len)
    return bvlc + npdu + apdu


def build_stp_bpdu(
    version: int = 0,
    bpdu_type: int = 0x00,
    flags: int = 0x01,
    root_prio: int = 0x8000,
    root_mac: bytes = b"\x00\x1A\x2B\x3C\x4D\x5E",
    root_path_cost: int = 0,
    bridge_prio: int = 0x8000,
    bridge_mac: bytes = b"\x00\x1A\x2B\x3C\x4D\x5E",
    port_id: int = 0x8001,
    with_llc: bool = True,
) -> bytes:
    """Builds a synthetic 802.1D/802.1w STP BPDU frame."""
    body = bytearray()
    body.extend(struct.pack(">HBB", 0x0000, version, bpdu_type))
    body.append(flags)
    body.extend(struct.pack(">H", root_prio))
    body.extend(root_mac)
    body.extend(struct.pack(">I", root_path_cost))
    body.extend(struct.pack(">H", bridge_prio))
    body.extend(bridge_mac)
    body.extend(struct.pack(">H", port_id))
    # Timer fields: Message Age, Max Age, Hello Time, Forward Delay
    body.extend(struct.pack(">HHHH", 0x0000, 0x1400, 0x0200, 0x0F00))

    if with_llc:
        return b"\x42\x42\x03" + bytes(body)
    return bytes(body)


class TestDpiDecoders(unittest.TestCase):
    """Tests passive Layer 2 / Layer 4 Enterprise DPI Decoders."""

    def test_ubnt_usw_switch_dissection(self):
        """Tests UBNT parser with synthetic USW-24-PoE payload."""
        payload = build_ubnt_payload(
            version=1,
            mac=b"\x74\x83\xC2\x11\x22\x33",
            firmware="6.5.32.14505",
            hostname="Core-USW-24-PoE",
            model="USW-24-PoE",
        )
        res = UbntDiscoveryDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["protocol"], "UBNT")
        self.assertEqual(res["type"], "switch")
        self.assertEqual(res["archetype"], "HARDWARE_ASIC_SWITCH")
        self.assertEqual(res["kernel_turnaround_us"], KERNEL_PRIOR_ASIC_SWITCH_MEAN_US)
        self.assertEqual(res["kernel_prior_std_us"], 1.5)
        self.assertEqual(res["mac"], "74:83:C2:11:22:33")
        self.assertEqual(res["hostname"], "Core-USW-24-PoE")
        self.assertEqual(res["firmware"], "6.5.32.14505")
        self.assertEqual(res["model"], "Ubiquiti USW-24-PoE")

    def test_ubnt_u6_pro_ap_dissection(self):
        """Tests UBNT parser with synthetic UniFi U6-Pro AP payload."""
        payload = build_ubnt_payload(
            version=2,
            mac=b"\x68\xD7\x9A\xAA\xBB\xCC",
            firmware="6.2.49.14111",
            hostname="Floor2-AP-U6-Pro",
            model="U6-Pro",
        )
        res = UbntDiscoveryDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "wlan_ap")
        self.assertEqual(res["archetype"], "ROUTER_AP_STACK")
        self.assertEqual(res["kernel_turnaround_us"], KERNEL_PRIOR_ROUTER_AP_MEAN_US)
        self.assertEqual(res["kernel_prior_std_us"], 8.0)
        self.assertEqual(res["mac"], "68:D7:9A:AA:BB:CC")

    def test_mikrotik_crs328_switch_dissection(self):
        """Tests MNDP parser with synthetic CRS328 switch payload."""
        payload = build_mndp_payload(
            mac=b"\x48\x8F\x5A\x12\x34\x56",
            identity="Switch-CRS328-24P",
            version="7.14.3",
            board="CRS328-24P-4S+RM",
            arch="arm",
        )
        res = MikrotikMndpDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["protocol"], "MNDP")
        self.assertEqual(res["type"], "switch")
        self.assertEqual(res["archetype"], "HARDWARE_ASIC_SWITCH")
        self.assertEqual(res["kernel_turnaround_us"], KERNEL_PRIOR_ASIC_SWITCH_MEAN_US)
        self.assertEqual(res["mac"], "48:8F:5A:12:34:56")
        self.assertEqual(res["hostname"], "Switch-CRS328-24P")
        self.assertEqual(res["firmware"], "RouterOS 7.14.3")
        self.assertEqual(res["model"], "MikroTik CRS328-24P-4S+RM")
        self.assertEqual(res["architecture"], "arm")

    def test_mikrotik_ccr2004_router_dissection(self):
        """Tests MNDP parser with synthetic CCR2004 router payload."""
        payload = build_mndp_payload(
            mac=b"\x08\x55\x31\x01\x02\x03",
            identity="Gateway-CCR2004",
            version="7.15.2",
            board="CCR2004-1G-12S+2XS",
            arch="arm64",
        )
        res = MikrotikMndpDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["type"], "router")
        self.assertEqual(res["archetype"], "ROUTER_AP_STACK")
        self.assertEqual(res["kernel_turnaround_us"], KERNEL_PRIOR_ROUTER_AP_MEAN_US)
        self.assertEqual(res["kernel_prior_std_us"], 8.0)

    def test_bacnet_iam_announcement(self):
        """Tests BACnet/IP parser with synthetic I-Am controller announcement."""
        payload = build_bacnet_iam_payload(device_instance=54321)
        res = BacnetIpDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["protocol"], "BACNET_IP")
        self.assertTrue(res["is_controller"])
        self.assertEqual(res["service"], "I-Am")
        self.assertEqual(res["device_instance"], 54321)
        self.assertEqual(res["archetype"], "BACNET_FIELD_CONTROLLER")
        self.assertEqual(res["kernel_turnaround_us"], KERNEL_PRIOR_BACNET_CTRL_MEAN_US)
        self.assertEqual(res["kernel_prior_std_us"], 25.0)
        self.assertEqual(res["type"], "iot_controller")
        self.assertIn("54321", res["model"])

    def test_bacnet_whois_query_distinction(self):
        """Tests BACnet/IP parser distinguishing Who-Is query from client workstation."""
        payload = build_bacnet_whois_payload()
        res = BacnetIpDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["protocol"], "BACNET_IP")
        self.assertFalse(res["is_controller"])
        self.assertEqual(res["service"], "Who-Is")
        self.assertEqual(res["archetype"], "WORKSTATION")
        self.assertIsNone(res["kernel_turnaround_us"])
        self.assertEqual(res["type"], "workstation")

    def test_stp_bpdu_root_bridge_dissection(self):
        """Tests STP BPDU parser with Root Bridge equal to Bridge MAC (Root Bridge scenario)."""
        mac = b"\x00\x1A\x2B\x3C\x4D\x5E"
        payload = build_stp_bpdu(
            version=0,
            bpdu_type=0x00,
            flags=0x01,
            root_mac=mac,
            root_path_cost=0,
            bridge_mac=mac,
            with_llc=True,
        )
        res = StpBpduDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["protocol"], "STP_BPDU")
        self.assertEqual(res["stp_version"], "STP (802.1D)")
        self.assertTrue(res["is_root_bridge"])
        self.assertEqual(res["root_bridge_mac"], "00:1A:2B:3C:4D:5E")
        self.assertEqual(res["bridge_mac"], "00:1A:2B:3C:4D:5E")
        self.assertEqual(res["root_path_cost"], 0)
        self.assertTrue(res["tc_flag"])
        self.assertEqual(res["archetype"], "HARDWARE_ASIC_SWITCH")
        self.assertEqual(res["kernel_turnaround_us"], KERNEL_PRIOR_ASIC_SWITCH_MEAN_US)

    def test_rstp_bpdu_non_root_dissection(self):
        """Tests RSTP BPDU parser where Root Bridge differs from Transmitting Bridge."""
        root_mac = b"\x00\x11\x22\x33\x44\x55"
        bridge_mac = b"\x00\xAA\xBB\xCC\xDD\xEE"
        payload = build_stp_bpdu(
            version=2,
            bpdu_type=0x02,
            flags=0x7C,
            root_mac=root_mac,
            root_path_cost=20000,
            bridge_mac=bridge_mac,
            with_llc=False,
        )
        res = StpBpduDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["stp_version"], "RSTP (802.1w)")
        self.assertEqual(res["bpdu_type"], "RSTP")
        self.assertFalse(res["is_root_bridge"])
        self.assertEqual(res["root_bridge_mac"], "00:11:22:33:44:55")
        self.assertEqual(res["bridge_mac"], "00:AA:BB:CC:DD:EE")
        self.assertEqual(res["root_path_cost"], 20000)

    def test_dpi_dispatcher_routing(self):
        """Tests DpiDispatcher routing across ports, LLC prefixes, and heuristics."""
        dispatcher = DpiDispatcher()

        # 1. UBNT over UDP 10001
        ubnt_pkt = build_ubnt_payload()
        res_ubnt = dispatcher.dispatch(ubnt_pkt, dst_port=10001)
        self.assertIsNotNone(res_ubnt)
        self.assertEqual(res_ubnt["protocol"], "UBNT")

        # 2. MNDP over UDP 5678
        mndp_pkt = build_mndp_payload()
        res_mndp = dispatcher.dispatch(mndp_pkt, src_port=5678)
        self.assertIsNotNone(res_mndp)
        self.assertEqual(res_mndp["protocol"], "MNDP")

        # 3. BACnet over UDP 47808
        bac_pkt = build_bacnet_iam_payload()
        res_bac = dispatcher.dispatch(bac_pkt, dst_port=47808)
        self.assertIsNotNone(res_bac)
        self.assertEqual(res_bac["protocol"], "BACNET_IP")

        # 4. STP BPDU over LLC / Multicast destination
        stp_pkt = build_stp_bpdu(with_llc=True)
        res_stp = dispatcher.dispatch(stp_pkt, dst_mac="01:80:C2:00:00:00")
        self.assertIsNotNone(res_stp)
        self.assertEqual(res_stp["protocol"], "STP_BPDU")

        # 5. Heuristic fallback without ports
        res_heur = dispatcher.dispatch(stp_pkt)
        self.assertIsNotNone(res_heur)
        self.assertEqual(res_heur["protocol"], "STP_BPDU")

    def test_defensive_truncation_and_corrupt_payloads(self):
        """Tests zero-crash defensive parsing on empty, truncated, and corrupt payloads."""
        dispatcher = DpiDispatcher()

        # Zero length and None checks
        self.assertIsNone(dispatcher.dispatch(b""))
        self.assertIsNone(UbntDiscoveryDecoder.decode(b""))
        self.assertIsNone(MikrotikMndpDecoder.decode(b""))
        self.assertIsNone(BacnetIpDecoder.decode(b""))
        self.assertIsNone(StpBpduDecoder.decode(b""))

        # Truncated headers (<4 bytes)
        self.assertIsNone(UbntDiscoveryDecoder.decode(b"\x01\x00"))
        self.assertIsNone(MikrotikMndpDecoder.decode(b"\x00\x01"))
        self.assertIsNone(BacnetIpDecoder.decode(b"\x81\x0A\x00"))
        self.assertIsNone(StpBpduDecoder.decode(b"\x42\x42\x03\x00\x00"))

        # Truncated TLV length claims 200 bytes but buffer is 5 bytes
        bogus_ubnt = b"\x01\x00\x00\x05\x01\x00\xC8\xAA"
        res_bogus_ubnt = UbntDiscoveryDecoder.decode(bogus_ubnt)
        self.assertIsNone(res_bogus_ubnt)

        bogus_mndp = b"\x00\x01\x00\xC8\xAA"
        res_bogus_mndp = MikrotikMndpDecoder.decode(bogus_mndp)
        self.assertIsNone(res_bogus_mndp)

        bogus_stp = b"\x00\x00\x00\x00" + b"\x00" * 20  # <35 bytes
        self.assertIsNone(StpBpduDecoder.decode(bogus_stp))

    def test_payload_sanitization_and_json_invariance(self):
        """Tests that all decoder outputs are strictly JSON round-trip invariant."""
        decoders_and_payloads = [
            (UbntDiscoveryDecoder.decode, build_ubnt_payload()),
            (MikrotikMndpDecoder.decode, build_mndp_payload()),
            (BacnetIpDecoder.decode, build_bacnet_iam_payload()),
            (BacnetIpDecoder.decode, build_bacnet_whois_payload()),
            (StpBpduDecoder.decode, build_stp_bpdu()),
        ]

        for decode_fn, payload in decoders_and_payloads:
            res = decode_fn(payload)
            self.assertIsNotNone(res)
            # Assert JSON round-trip invariance
            serialized = json.dumps(res)
            deserialized = json.loads(serialized)
            self.assertEqual(res, deserialized)

    def test_telemetry_ledger_stp_integration(self):
        """Tests persistence of STP BPDU topological tree constraints into spatial_ledger.db."""
        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "test_ledger.db")
            ledger = TelemetryLedger(db_path=db_path)
            ledger.record_stp_topology(
                root_bridge_mac="00:1A:2B:3C:4D:5E",
                root_path_cost=19,
                designated_bridge_mac="00:1A:2B:3C:4D:99",
                port_id=0x8004,
                is_root_bridge=False,
                stp_version="RSTP (802.1w)",
                tc_flag=True,
            )

            conn = sqlite3.connect(db_path)
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT root_bridge_mac, root_path_cost, designated_bridge_mac, port_id, is_root_bridge, stp_version, tc_flag FROM stp_topology_ledger"
                )
                row = cur.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], "00:1A:2B:3C:4D:5E")
                self.assertEqual(row[1], 19)
                self.assertEqual(row[2], "00:1A:2B:3C:4D:99")
                self.assertEqual(row[3], 0x8004)
                self.assertEqual(row[4], 0)
                self.assertEqual(row[5], "RSTP (802.1w)")
                self.assertEqual(row[6], 1)
            finally:
                conn.close()

    def test_sweeper_handle_sniffed_packet_integration(self):
        """Verifies SubnetSweeper._handle_sniffed_packet routes packets into DIP and inferred profiles."""
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, UDP
        from graphpath.cli.sweep import SubnetSweeper

        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "test_ledger.db")
            sweeper = SubnetSweeper(
                subnet_cidr="192.168.1.0/24",
                interface=None,
                api_url=None,
            )
            sweeper.ledger = TelemetryLedger(db_path=db_path)

            # 1. Ingest Ubiquiti USW switch packet
            ubnt_raw = build_ubnt_payload(
                mac=b"\x74\x83\xC2\x11\x22\x33",
                model="USW-24-PoE",
                hostname="Core-USW-24-PoE",
            )
            scapy_ubnt = (
                Ether(src="74:83:c2:11:22:33", dst="ff:ff:ff:ff:ff:ff")
                / IP(src="192.168.1.50", dst="255.255.255.255")
                / UDP(sport=10001, dport=10001)
                / ubnt_raw
            )
            sweeper._handle_sniffed_packet(scapy_ubnt)

            self.assertIn("192.168.1.50", sweeper.inferred_os_profiles)
            prof = sweeper.inferred_os_profiles["192.168.1.50"]
            self.assertEqual(prof["os_profile"], "HARDWARE_ASIC_SWITCH")
            self.assertEqual(sweeper.probed_kernel_turnarounds.get("192.168.1.50"), 4.0)

            # 2. Ingest BACnet/IP I-Am packet
            bac_raw = build_bacnet_iam_payload(device_instance=8888)
            scapy_bac = (
                Ether(src="00:10:e0:12:34:56", dst="ff:ff:ff:ff:ff:ff")
                / IP(src="192.168.1.60", dst="192.168.1.255")
                / UDP(sport=47808, dport=47808)
                / bac_raw
            )
            sweeper._handle_sniffed_packet(scapy_bac)

            self.assertIn("192.168.1.60", sweeper.inferred_os_profiles)
            bac_prof = sweeper.inferred_os_profiles["192.168.1.60"]
            self.assertEqual(bac_prof["os_profile"], "BACNET_FIELD_CONTROLLER")
            self.assertEqual(sweeper.probed_kernel_turnarounds.get("192.168.1.60"), 110.0)

            # 3. Ingest STP BPDU packet
            stp_raw = build_stp_bpdu(with_llc=True)
            scapy_stp = Ether(src="00:1a:2b:3c:4d:5e", dst="01:80:c2:00:00:00") / stp_raw
            sweeper._handle_sniffed_packet(scapy_stp)

            # Assert STP topology was logged to ledger
            conn = sqlite3.connect(db_path)
            try:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM stp_topology_ledger")
                count = cur.fetchone()[0]
                self.assertGreaterEqual(count, 1)
            finally:
                conn.close()

    def test_stp_bpdu_sysid_vlan_decomposition(self):
        """Verifies 16-bit Bridge Priority decomposes into Base Priority and SysID Extension / VLAN ID."""
        # Root Priority: 0x8014 -> Base 32768 (0x8000) + VLAN 20 (0x0014)
        # Bridge Priority: 0x9014 -> Base 36864 (0x9000) + VLAN 20 (0x0014)
        payload = build_stp_bpdu(
            root_prio=0x8014,
            bridge_prio=0x9014,
            root_path_cost=19,
            with_llc=True,
        )
        res = StpBpduDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["root_base_priority"], 32768)
        self.assertEqual(res["root_vlan_id"], 20)
        self.assertEqual(res["bridge_base_priority"], 36864)
        self.assertEqual(res["bridge_vlan_id"], 20)
        self.assertEqual(res["vlan_id"], 20)

        # Test TelemetryLedger persists vlan_id and prevents cross-VLAN collisions
        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "test_stp_vlan.db")
            ledger = TelemetryLedger(db_path=db_path)
            ledger.record_stp_topology(
                root_bridge_mac=res["root_bridge_mac"],
                root_path_cost=res["root_path_cost"],
                designated_bridge_mac=res["designated_bridge_mac"],
                port_id=res["port_id"],
                is_root_bridge=res["is_root_bridge"],
                stp_version=res["stp_version"],
                tc_flag=res["tc_flag"],
                vlan_id=res["vlan_id"],
            )

            conn = sqlite3.connect(db_path)
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT root_bridge_mac, vlan_id, root_path_cost FROM stp_topology_ledger"
                )
                row = cur.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], res["root_bridge_mac"])
                self.assertEqual(row[1], 20)
                self.assertEqual(row[2], 19)
            finally:
                conn.close()

    def test_bacnet_mstp_router_snet_prior_separation(self):
        """Verifies SNET presence isolates router prior (35.0us) from microcontroller prior (110.0us)."""
        payload = build_bacnet_routed_iam_payload(
            device_instance=5555, snet=200, sadr=b"\x0C"
        )
        res = BacnetIpDecoder.decode(payload)
        self.assertIsNotNone(res)
        self.assertTrue(res["is_mstp_routed"])
        self.assertEqual(res["snet"], 200)
        self.assertEqual(res["sadr"], "0c")
        # Top-level represents the IP-facing MS/TP router
        self.assertEqual(res["kernel_turnaround_us"], 35.0)
        # routed_device represents the downstream microcontroller
        self.assertIsNotNone(res["routed_device"])
        self.assertEqual(res["routed_device"]["kernel_turnaround_us"], 110.0)

        # Sweeper integration: ensure sweeper records both priors without collision
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, UDP
        from graphpath.cli.sweep import SubnetSweeper

        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "test_bacnet_routed.db")
            sweeper = SubnetSweeper(
                subnet_cidr="192.168.1.0/24",
                interface=None,
                api_url=None,
            )
            sweeper.ledger = TelemetryLedger(db_path=db_path)

            scapy_bac = (
                Ether(src="00:10:e0:ab:cd:ef", dst="ff:ff:ff:ff:ff:ff")
                / IP(src="192.168.1.75", dst="192.168.1.255")
                / UDP(sport=47808, dport=47808)
                / payload
            )
            sweeper._handle_sniffed_packet(scapy_bac)

            # IP gets the MS/TP router prior
            self.assertEqual(sweeper.probed_kernel_turnarounds.get("192.168.1.75"), 35.0)
            # Composite (IP, SNET, SADR) gets the field microcontroller prior
            mstp_key = ("192.168.1.75", 200, "0c")
            self.assertIn(mstp_key, sweeper.routed_microcontroller_priors)
            self.assertEqual(
                sweeper.routed_microcontroller_priors[mstp_key]["kernel_turnaround_us"],
                110.0,
            )

    def test_telemetry_anomaly_filter_and_robust_scaling(self):
        """Verifies MAD Z-score scaling, log path cost compression, and Mahalanobis anomaly filtering."""
        # 1. robust_z_score
        history = [10.0, 10.1, 9.9, 10.2, 9.8]
        z_norm = robust_z_score(10.0, history)
        self.assertAlmostEqual(z_norm, 0.0, places=2)
        z_outlier = robust_z_score(50.0, history)
        self.assertGreater(z_outlier, 10.0)

        # Flat history (MAD == 0) must not throw ZeroDivisionError
        z_flat = robust_z_score(10.0, [10.0, 10.0, 10.0])
        self.assertEqual(z_flat, 0.0)

        # 2. normalize_stp_path_cost
        self.assertEqual(normalize_stp_path_cost(0), 0.0)
        self.assertGreater(normalize_stp_path_cost(4), 0.0)
        self.assertLess(normalize_stp_path_cost(4), normalize_stp_path_cost(19))
        self.assertAlmostEqual(normalize_stp_path_cost(200_000_000), 1.0, places=3)
        self.assertEqual(normalize_stp_path_cost(250_000_000), 1.0)

        # 3. TelemetryAnomalyFilter
        filter_inst = TelemetryAnomalyFilter()
        is_valid, d2, w = filter_inst.evaluate(35.0, 5.0)
        self.assertTrue(is_valid)
        self.assertLess(d2, 1.0)
        self.assertGreater(w, 0.5)

        # Extreme outlier rejection
        is_valid_outlier, d2_outlier, w_outlier = filter_inst.evaluate(500.0, 100.0)
        self.assertFalse(is_valid_outlier)
        self.assertGreater(d2_outlier, filter_inst.CHI2_ALPHA_001_DF2)
        self.assertLess(w_outlier, 0.01)

        # Variance modulation
        mod_r = filter_inst.modulate_variance(10.0, weight=0.1)
        self.assertAlmostEqual(mod_r, 100.0)

        # 4. BayesianTurnaround conjugate update
        bt = BayesianTurnaround(mean=35.0, variance=25.0, samples=[], prior_mean=35.0, prior_var=25.0)
        self.assertEqual(float(bt), 35.0)
        self.assertEqual(bt["prior_mu"], 35.0)

        # Update with fast switch measurements (around 4.0us)
        observations = [4.1, 3.9, 4.0, 4.2, 3.8, 4.0, 4.1, 3.9, 4.0, 4.0]
        updated = bt.update_with_observations(observations, measurement_std=2.0)
        # Posterior mean should shift sharply towards 4.0
        self.assertLess(float(updated), 10.0)
        # Posterior variance should be sharply reduced from 25.0
        self.assertLess(updated["variance"], 1.0)
        self.assertEqual(len(updated["samples"]), 10)


if __name__ == "__main__":
    unittest.main()
