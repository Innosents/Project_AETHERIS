"""
Unit tests for ChassisParser & LLDP Z-Axis Physics (Phase 26).
Validates AWG 23 Joule heating / DC loop resistance deconvolution,
stateless TIA TR-41 LLDP-MED Power-via-MDI extraction, and SpanTapAdapter integration.
"""

import pytest
import struct
from unittest.mock import MagicMock
from scapy.all import Ether, Raw

from aetheris.core.parsers.chassis_parser import (
    calculate_z_axis,
    extract_lldp_med_telemetry,
    process_lldp_frame,
    AWG23_RESISTANCE_KM,
    POE_CURRENT_AMPS,
    MOCK_RX_DRAW_WATTS,
    TIA_TR41_LLDP_MED_PREFIX,
)
from aetheris.infrastructure.adapters.span_tap_adapter import SpanTapAdapter


class TestChassisZAxisPhysics:
    def test_physical_constants_invariance(self):
        assert AWG23_RESISTANCE_KM == 0.0686
        assert POE_CURRENT_AMPS == 0.350
        assert MOCK_RX_DRAW_WATTS == 14.10

    def test_calculate_z_axis_zero_loss(self):
        # Transmit power equals mock receiver draw -> 0 meters drop
        length = calculate_z_axis(14.10)
        assert length == 0.0

    def test_calculate_z_axis_calibrated_distance(self):
        # For 100 meters:
        # i^2 * R = (0.35)^2 * 0.0686 = 0.1225 * 0.0686 = 0.0084035 W/m
        # For 100m, w_loss = 0.84035 W
        # w_tx = 14.10 + 0.84035 = 14.94035 W
        w_tx = 14.10 + (100.0 * (POE_CURRENT_AMPS**2) * AWG23_RESISTANCE_KM)
        length = calculate_z_axis(w_tx)
        assert round(length, 2) == 100.0

    def test_calculate_z_axis_50m_drop(self):
        w_tx = 14.10 + (50.0 * (POE_CURRENT_AMPS**2) * AWG23_RESISTANCE_KM)
        length = calculate_z_axis(w_tx)
        assert round(length, 2) == 50.0


class TestLldpMedParser:
    def test_extract_lldp_med_telemetry_valid_bytes(self):
        # Construct synthetic frame:
        # Prefix b"\x00\x12\xbb\x02" + 1 byte subtype flags + 2 bytes power (15400 mW = 15.4 W)
        power_mw = 15400
        power_bytes = struct.pack(">H", power_mw)
        frame_bytes = b"\x01\x80\xc2\x00\x00\x0e" + TIA_TR41_LLDP_MED_PREFIX + b"\x00" + power_bytes + b"\x00\x00"

        res = extract_lldp_med_telemetry(frame_bytes)
        assert res is not None
        assert res["w_tx"] == 15.4
        assert res["raw_hex"] == power_bytes.hex()
        expected_len = (15.4 - 14.10) / ((0.35**2) * 0.0686)
        assert res["z_axis_m"] == round(expected_len, 2)

    def test_extract_lldp_med_telemetry_scapy_packet(self):
        power_mw = 14940
        power_bytes = struct.pack(">H", power_mw)
        payload = b"\xaa\xbb" + TIA_TR41_LLDP_MED_PREFIX + b"\x00" + power_bytes
        pkt = Ether(src="00:11:22:33:44:55", dst="01:80:c2:00:00:0e") / Raw(load=payload)

        res = extract_lldp_med_telemetry(pkt)
        assert res is not None
        assert res["w_tx"] == 14.94
        assert res["raw_hex"] == power_bytes.hex()

    def test_extract_lldp_med_telemetry_missing_tlv(self):
        frame = b"\x01\x80\xc2\x00\x00\x0e\x00\x11\x22\x33\x44\x55\x88\xcc\x00\x00"
        res = extract_lldp_med_telemetry(frame)
        assert res is None

    def test_extract_lldp_med_telemetry_truncated(self):
        # Prefix present but truncated before power bytes
        frame = b"\x00\x12\xbb\x02\x00"
        res = extract_lldp_med_telemetry(frame)
        assert res is None

    def test_process_lldp_frame_boolean_contract(self):
        valid_payload = b"HEADER" + TIA_TR41_LLDP_MED_PREFIX + b"\x01" + struct.pack(">H", 15000)
        assert process_lldp_frame(valid_payload) is True

        invalid_payload = b"RANDOM_ETHERNET_FRAME_WITHOUT_LLDP"
        assert process_lldp_frame(invalid_payload) is False


class TestSpanTapAdapterDelegateIntegration:
    def test_span_tap_adapter_registers_and_dispatches_lldp(self):
        adapter = SpanTapAdapter(interface="eth0")
        processed_packets = []

        def lldp_delegate(pkt):
            if process_lldp_frame(pkt):
                processed_packets.append(pkt)

        adapter.register_delegate("chassis_intelligence", lldp_delegate)

        # Synthetic LLDP frame with MAC_LLDP (01:80:c2:00:00:0e)
        power_bytes = struct.pack(">H", 14800)
        payload = TIA_TR41_LLDP_MED_PREFIX + b"\x00" + power_bytes
        lldp_frame = Ether(src="00:aa:bb:cc:dd:ee", dst="01:80:c2:00:00:0e") / Raw(load=payload)

        adapter._packet_callback(lldp_frame)

        assert adapter.stats["chassis_frames"] == 1
        assert len(processed_packets) == 1

        adapter.unregister_delegate("chassis_intelligence", lldp_delegate)

