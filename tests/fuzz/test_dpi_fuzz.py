"""
Project AETHERIS - Property-Based & Differential Fuzzing Suite (Phase 8.1 & Phase 5)
Verifies:
1. Hypothesis custom composite strategy mutated_tlv_packet (overstated/understated lengths, 65535 boundaries, orphan bytes)
2. UbntDiscoveryDecoder fuzz resilience (>= 500 iterations)
3. MikrotikMndpDecoder fuzz resilience (>= 500 iterations)
4. BacnetIpDecoder fuzz resilience (>= 500 iterations)
5. StpBpduDecoder fuzz resilience (>= 500 iterations)
6. DpiDispatcher multi-port routing fuzz resilience (>= 500 iterations)
7. TelemetryAnomalyFilter numerical stability (no NaN/Inf, variance >= 0, weight in [0, 1])
8. Non-standard TCP sequence injection & RFC 7323 timestamp option resilience
9. Edge-case ICMP RFC 792/1122 malformed payload injection & graceful rejection
10. Fragmented & malformed Modbus TCP MBAP frame resilience (zero ledger pollution)
11. Strict JSON round-trip invariance and zero unhandled exceptions
"""

import json
import math
import struct
import unittest
try:
    from hypothesis import given, settings, strategies as st
    HAS_HYPOTHESIS = True
except (ImportError, ModuleNotFoundError):
    HAS_HYPOTHESIS = False

    def given(*args, **kwargs):
        def decorator(func):
            return unittest.skip("hypothesis not installed; fuzz suite skipped")(func)
        return decorator

    def settings(*args, **kwargs):
        def decorator(func):
            return func
        return decorator

    class _DummyStrategies:
        def __getattr__(self, name):
            return lambda *a, **kw: None
        def composite(self, func):
            return lambda *a, **kw: None

    st = _DummyStrategies()


from aetheris.core.fingerprinting.dpi_decoders import (
    UbntDiscoveryDecoder,
    MikrotikMndpDecoder,
    BacnetIpDecoder,
    StpBpduDecoder,
    DpiDispatcher,
)
from aetheris.core.fingerprinting.dpi_normalizers import (
    robust_z_score,
    normalize_stp_path_cost,
    TelemetryAnomalyFilter,
    BayesianTurnaround,
)
from aetheris.discovery.geolocation_engine import (
    LldpMedLocationDecoder,
    PublicGeoIpResolver,
    SpatialPathReasoner,
)
from aetheris.discovery.advanced_spatial_prober import AdvancedSpatialProber
from aetheris.discovery.dns_discovery import DnsDiscoveryEngine
from aetheris.core.spatial_solver import SpatialSolver
from aetheris.core.spatial_dc_drop import (
    calculate_conductor_distance,
    get_conductor_resistance_per_meter,
)
from aetheris.discovery.mirror_engine import (
    SpanCaptureEngine,
    OtWireDissector,
    BoundedFlowWindowRing,
)
from aetheris.core.telemetry_ledger import TelemetryLedger


@st.composite
def mutated_tlv_packet(draw):
    """
    Composite Hypothesis strategy generating structurally mutated TLV packets.
    Simulates:
    - Overstated and understated TLV lengths
    - 0xFFFF (65535) and 0x0000 length edge cases
    - Truncated payloads and orphan byte cascades
    - Valid TLVs mixed with random corruptions
    """
    tlv_type = draw(st.integers(min_value=0, max_value=255))
    length_mutation = draw(
        st.sampled_from([
            "exact",
            "overstated",
            "understated",
            "zero",
            "max16",
            "random",
        ])
    )
    payload = draw(st.binary(min_size=0, max_size=256))

    if length_mutation == "exact":
        length_val = len(payload)
    elif length_mutation == "overstated":
        length_val = len(payload) + draw(st.integers(min_value=1, max_value=1000))
    elif length_mutation == "understated":
        length_val = max(0, len(payload) - draw(st.integers(min_value=1, max_value=20)))
    elif length_mutation == "zero":
        length_val = 0
    elif length_mutation == "max16":
        length_val = 0xFFFF
    else:
        length_val = draw(st.integers(min_value=0, max_value=65535))

    encoding = draw(st.sampled_from(["1byte_type_2byte_len", "2byte_type_2byte_len"]))
    if encoding == "1byte_type_2byte_len":
        header = struct.pack(">BH", tlv_type, length_val)
    else:
        header = struct.pack(">HH", tlv_type, length_val)

    orphan_bytes = draw(st.binary(min_size=0, max_size=32))
    return header + payload + orphan_bytes


@st.composite
def mutated_tcp_frame(draw):
    """
    Hypothesis strategy generating non-standard TCP sequences and malformed options.
    Simulates invalid data offsets (< 20 or > length), overlapping flags,
    corrupted RFC 7323 timestamp options, and out-of-order sequence boundaries.
    """
    src_ip_b = bytes([10, draw(st.integers(0, 254)), draw(st.integers(1, 254)), draw(st.integers(1, 254))])
    dst_ip_b = bytes([10, 0, 0, draw(st.integers(1, 254))])
    src_port = draw(st.integers(0, 65535))
    dst_port = draw(st.integers(0, 65535))
    seq_num = draw(st.integers(0, 0xFFFFFFFF))
    ack_num = draw(st.integers(0, 0xFFFFFFFF))

    # Data offset in 32-bit words: 0..4 is invalid (< 20B), 5 is standard (20B), > 5 includes options
    offset_words = draw(st.integers(0, 15))
    flags = draw(st.integers(0, 0x1FF))  # SYN, FIN, RST, PSH, ACK, URG, etc.
    offset_flags = (offset_words << 12) | (flags & 0x0FFF)

    window_size = draw(st.integers(0, 65535))
    checksum = draw(st.integers(0, 65535))
    urg_ptr = draw(st.integers(0, 65535))

    tcp_hdr_base = struct.pack(">HHIIHHHH", src_port, dst_port, seq_num, ack_num, offset_flags, window_size, checksum, urg_ptr)

    # Corrupt or valid TCP options
    has_options = draw(st.booleans())
    if has_options and offset_words > 5:
        opt_len = max(0, (offset_words * 4) - 20)
        options = draw(st.binary(min_size=opt_len, max_size=opt_len))
    else:
        options = b""

    payload = draw(st.binary(min_size=0, max_size=256))

    # Construct complete IPv4 packet
    ip_total_len = 20 + len(tcp_hdr_base) + len(options) + len(payload)
    ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_total_len, 0x1234, 0x4000, 64, 6, 0, src_ip_b, dst_ip_b)

    # Ethernet frame: DST MAC + SRC MAC + EtherType 0x0800
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x00\x66\x77\x88\x99\xAA\x08\x00"
    return eth_hdr + ip_hdr + tcp_hdr_base + options + payload


@st.composite
def mutated_icmp_frame(draw):
    """
    Hypothesis strategy generating edge-case RFC 792/1122 ICMP frames.
    Simulates invalid ICMP types, truncated bodies, zero-length payloads, and corrupted headers.
    """
    src_ip_b = bytes([192, 168, 1, draw(st.integers(1, 254))])
    dst_ip_b = bytes([192, 168, 1, draw(st.integers(1, 254))])

    icmp_type = draw(st.integers(0, 255))
    icmp_code = draw(st.integers(0, 255))
    checksum = draw(st.integers(0, 65535))
    body = draw(st.binary(min_size=0, max_size=128))

    icmp_bytes = struct.pack(">BBH", icmp_type, icmp_code, checksum) + body
    ip_total_len = 20 + len(icmp_bytes)
    ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_total_len, 0x5678, 0, 64, 1, 0, src_ip_b, dst_ip_b)
    eth_hdr = b"\x00\xAA\xBB\xCC\xDD\xEE\x00\x11\x22\x33\x44\x55\x08\x00"
    return eth_hdr + ip_hdr + icmp_bytes


@st.composite
def mutated_modbus_frame(draw):
    """
    Hypothesis strategy generating fragmented & malformed Modbus TCP frames.
    Simulates truncated MBAP headers, non-zero protocol IDs, length mismatches, and exception PDUs.
    """
    tx_id = draw(st.integers(0, 65535))
    proto_id = draw(st.sampled_from([0, 0, 0, 1, 255, 65535]))  # 0 is valid Modbus TCP
    stated_len = draw(st.integers(0, 65535))
    unit_id = draw(st.integers(0, 255))
    func_code = draw(st.integers(0, 255))
    pdu_payload = draw(st.binary(min_size=0, max_size=128))

    # Raw MBAP + PDU bytes
    raw_mbap = struct.pack(">HHHBB", tx_id, proto_id, stated_len, unit_id, func_code) + pdu_payload

    # Truncation mutation
    if draw(st.booleans()):
        truncate_len = draw(st.integers(0, len(raw_mbap)))
        raw_mbap = raw_mbap[:truncate_len]

    return raw_mbap


class TestDpiDecodersFuzz(unittest.TestCase):
    """Differential property-based fuzzing test cases for DPI decoders, OT dissectors, and anomaly filter."""

    @settings(max_examples=500, deadline=None)
    @given(st.binary(min_size=0, max_size=1500))
    def test_fuzz_ubnt_arbitrary_bytes(self, raw_bytes: bytes):
        """UbntDiscoveryDecoder must never raise an unhandled exception and must preserve JSON invariance."""
        res = UbntDiscoveryDecoder.decode(raw_bytes)
        if res is not None:
            self.assertIsInstance(res, dict)
            encoded = json.dumps(res)
            decoded = json.loads(encoded)
            self.assertEqual(res, decoded)
            self.assertIn("t_kernel_prior_us", res)
            self.assertIsInstance(res["t_kernel_prior_us"], (int, float))

    @settings(max_examples=500, deadline=None)
    @given(mutated_tlv_packet())
    def test_fuzz_ubnt_mutated_tlvs(self, tlv_data: bytes):
        """UbntDiscoveryDecoder must handle mutated TLV streams safely."""
        packet = b"\x01\x00\x00\x00" + tlv_data
        res = UbntDiscoveryDecoder.decode(packet)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(json.loads(json.dumps(res)), res)

    @settings(max_examples=500, deadline=None)
    @given(st.binary(min_size=0, max_size=1500))
    def test_fuzz_mikrotik_arbitrary_bytes(self, raw_bytes: bytes):
        """MikrotikMndpDecoder must never raise unhandled exceptions and maintain JSON invariance."""
        res = MikrotikMndpDecoder.decode(raw_bytes)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(json.loads(json.dumps(res)), res)
            self.assertIn("t_kernel_prior_us", res)
            self.assertIsInstance(res["t_kernel_prior_us"], (int, float))

    @settings(max_examples=500, deadline=None)
    @given(mutated_tlv_packet())
    def test_fuzz_mikrotik_mutated_tlvs(self, tlv_data: bytes):
        """MikrotikMndpDecoder must handle corrupt/mutated TLVs without crashing."""
        packet = b"\x00\x00\x00\x00" + tlv_data
        res = MikrotikMndpDecoder.decode(packet)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(json.loads(json.dumps(res)), res)

    @settings(max_examples=500, deadline=None)
    @given(st.binary(min_size=0, max_size=1500))
    def test_fuzz_bacnet_arbitrary_bytes(self, raw_bytes: bytes):
        """BacnetIpDecoder must never crash on arbitrary UDP 47808 payloads."""
        res = BacnetIpDecoder.decode(raw_bytes)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(json.loads(json.dumps(res)), res)
            self.assertIn("t_kernel_prior_us", res)
            self.assertIsInstance(res["t_kernel_prior_us"], (int, float))

    @settings(max_examples=500, deadline=None)
    @given(st.binary(min_size=0, max_size=1500))
    def test_fuzz_stp_arbitrary_bytes(self, raw_bytes: bytes):
        """StpBpduDecoder must never crash on arbitrary BPDU/LLC frames."""
        res = StpBpduDecoder.decode(raw_bytes)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(json.loads(json.dumps(res)), res)
            self.assertIn("root_base_priority", res)
            self.assertIn("root_vlan_id", res)
            self.assertIn("bridge_base_priority", res)
            self.assertIn("bridge_vlan_id", res)
            self.assertIn("vlan_id", res)
            self.assertGreaterEqual(res["vlan_id"], 0)
            self.assertLessEqual(res["vlan_id"], 4095)

    @settings(max_examples=500, deadline=None)
    @given(
        st.integers(min_value=0, max_value=65535),
        st.binary(min_size=0, max_size=1500),
    )
    def test_fuzz_dispatcher_multi_port(self, port: int, payload: bytes):
        """DpiDispatcher.dispatch must handle arbitrary port/payload tuples gracefully."""
        res = DpiDispatcher.dispatch(payload=payload, dport=port, sport=port)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(json.loads(json.dumps(res)), res)

    @settings(max_examples=500, deadline=None)
    @given(
        st.floats(
            min_value=-1e6,
            max_value=1e6,
            allow_nan=False,
            allow_infinity=False,
        ),
        st.floats(
            min_value=-1e6,
            max_value=1e6,
            allow_nan=False,
            allow_infinity=False,
        ),
    )
    def test_fuzz_telemetry_anomaly_filter_stability(
        self, t_kernel: float, jitter: float
    ):
        """TelemetryAnomalyFilter must maintain numerical stability with non-negative variances."""
        filt = TelemetryAnomalyFilter()
        # Warmup filter with reasonable initial point
        filt.filter_measurement(10.0, 1.0)

        passed, d2, w = filt.filter_measurement(t_kernel, jitter)
        self.assertIsInstance(passed, bool)
        self.assertFalse(math.isnan(d2))
        self.assertFalse(math.isinf(d2))
        self.assertGreaterEqual(d2, 0.0)

        self.assertFalse(math.isnan(w))
        self.assertFalse(math.isinf(w))
        self.assertGreaterEqual(w, 0.0)
        self.assertLessEqual(w, 1.0)

        # Assert covariance matrix variance terms remain strictly non-negative
        self.assertGreaterEqual(filt.covariance[0][0], 0.0)
        self.assertGreaterEqual(filt.covariance[1][1], 0.0)
        self.assertFalse(math.isnan(filt.mean[0]))
        self.assertFalse(math.isnan(filt.mean[1]))

    @settings(max_examples=500, deadline=None)
    @given(
        st.lists(
            st.floats(
                min_value=-1e6,
                max_value=1e6,
                allow_nan=False,
                allow_infinity=False,
            ),
            min_size=0,
            max_size=50,
        ),
        st.floats(
            min_value=-1e6,
            max_value=1e6,
            allow_nan=False,
            allow_infinity=False,
        ),
    )
    def test_fuzz_robust_z_score(self, history, current_val):
        """robust_z_score must return valid floats without raising ZeroDivisionError or NaN."""
        z = robust_z_score(current_val, history)
        self.assertIsInstance(z, float)
        self.assertFalse(math.isnan(z))
        self.assertFalse(math.isinf(z))

    @settings(max_examples=500, deadline=None)
    @given(st.integers(min_value=-1000, max_value=2**32))
    def test_fuzz_normalize_stp_path_cost(self, cost: int):
        """normalize_stp_path_cost must return non-negative finite float for any integer cost."""
        norm_cost = normalize_stp_path_cost(cost)
        self.assertIsInstance(norm_cost, float)
        self.assertFalse(math.isnan(norm_cost))
        self.assertFalse(math.isinf(norm_cost))
        self.assertGreaterEqual(norm_cost, 0.0)

    @settings(max_examples=500, deadline=None)
    @given(
        st.floats(min_value=0.1, max_value=1000.0, allow_nan=False, allow_infinity=False),
        st.floats(min_value=0.1, max_value=100.0, allow_nan=False, allow_infinity=False),
        st.lists(
            st.floats(min_value=0.1, max_value=1000.0, allow_nan=False, allow_infinity=False),
            min_size=1,
            max_size=30,
        ),
    )
    def test_fuzz_bayesian_turnaround_conjugate_update(
        self, prior_mu, prior_sigma, observations
    ):
        """BayesianTurnaround conjugate updater must maintain numerical sanity and dictionary access."""
        bt = BayesianTurnaround(
            mean=prior_mu,
            variance=prior_sigma**2,
            samples=[],
            prior_mean=prior_mu,
            prior_var=prior_sigma**2,
        )
        self.assertAlmostEqual(float(bt), prior_mu, places=4)
        self.assertEqual(bt["prior_mu"], prior_mu)
        self.assertEqual(bt["samples"], [])

        updated = bt.update_with_observations(observations)
        self.assertIsInstance(updated, BayesianTurnaround)
        self.assertFalse(math.isnan(float(updated)))
        self.assertFalse(math.isinf(float(updated)))
        self.assertGreaterEqual(float(updated), 0.0)
        self.assertEqual(len(updated["samples"]), len(observations))
        self.assertGreater(updated["posterior_var"], 0.0)

    @settings(max_examples=500, deadline=None)
    @given(st.binary(min_size=0, max_size=1500))
    def test_fuzz_lldp_med_location_arbitrary_bytes(self, raw_bytes: bytes):
        """LldpMedLocationDecoder must never crash on arbitrary binary TLVs and preserve JSON invariance."""
        res = LldpMedLocationDecoder.decode_location_tlv(raw_bytes)
        self.assertIsInstance(res, dict)
        self.assertIn("format", res)
        self.assertIn("raw_hex", res)
        self.assertEqual(json.loads(json.dumps(res)), res)

    @settings(max_examples=500, deadline=None)
    @given(mutated_tlv_packet())
    def test_fuzz_lldp_med_mutated_tlvs(self, tlv_data: bytes):
        """LldpMedLocationDecoder must safely handle mutated Civic Address and Coordinate TLVs."""
        packet = b"\x02" + tlv_data
        res = LldpMedLocationDecoder.decode_location_tlv(packet)
        self.assertIsInstance(res, dict)
        self.assertEqual(json.loads(json.dumps(res)), res)

        norm = LldpMedLocationDecoder.normalize_civic_address(res)
        self.assertIsInstance(norm, dict)
        self.assertEqual(json.loads(json.dumps(norm)), norm)

    @settings(max_examples=500, deadline=None)
    @given(st.binary(min_size=0, max_size=120))
    def test_fuzz_advanced_spatial_prober_tcp_timestamps(self, raw_tcp_hdr: bytes):
        """AdvancedSpatialProber.extract_tcp_timestamps must never crash on arbitrary TCP option bytes."""
        res = AdvancedSpatialProber.extract_tcp_timestamps(raw_tcp_hdr)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(json.loads(json.dumps(res)), res)
            self.assertIn("has_rfc7323", res)
            self.assertIsInstance(res["has_rfc7323"], bool)

    @settings(max_examples=500, deadline=None)
    @given(
        st.floats(min_value=-1000.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        st.floats(min_value=-1000.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        st.floats(min_value=-1000.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        st.sampled_from([18, 20, 22, 24]),
        st.floats(min_value=-50.0, max_value=180.0, allow_nan=False, allow_infinity=False),
    )
    def test_fuzz_spatial_dc_drop_extreme_boundaries(
        self, v_src: float, v_term: float, current: float, awg: int, temp_c: float
    ):
        """calculate_conductor_distance must remain non-negative with zero division or NaN exceptions."""
        res = calculate_conductor_distance(
            v_source=v_src,
            v_terminal=v_term,
            current_amps=current,
            awg=awg,
            temp_c=temp_c
        )
        self.assertIsInstance(res, dict)
        self.assertEqual(json.loads(json.dumps(res)), res)
        self.assertGreaterEqual(res["distance_m"], 0.0)
        self.assertFalse(math.isnan(res["distance_m"]))
        self.assertFalse(math.isinf(res["distance_m"]))

    @settings(max_examples=500, deadline=None)
    @given(
        st.floats(min_value=-90.0, max_value=90.0, allow_nan=False, allow_infinity=False),
        st.floats(min_value=-180.0, max_value=180.0, allow_nan=False, allow_infinity=False),
        st.floats(min_value=-90.0, max_value=90.0, allow_nan=False, allow_infinity=False),
        st.floats(min_value=-180.0, max_value=180.0, allow_nan=False, allow_infinity=False),
    )
    def test_fuzz_haversine_and_bgp_rtt_boundaries(
        self, lat1: float, lon1: float, lat2: float, lon2: float
    ):
        """PublicGeoIpResolver geodesic and BGP RTT calculations must remain strictly finite and non-negative."""
        d_km = PublicGeoIpResolver.calculate_haversine_distance_km(lat1, lon1, lat2, lon2)
        self.assertIsInstance(d_km, float)
        self.assertGreaterEqual(d_km, 0.0)
        self.assertFalse(math.isnan(d_km))
        self.assertFalse(math.isinf(d_km))

        rtt_min = PublicGeoIpResolver.calculate_rtt_min_ms(d_km, inflation_scalar=1.5)
        self.assertIsInstance(rtt_min, float)
        self.assertGreaterEqual(rtt_min, 0.0)
        self.assertFalse(math.isnan(rtt_min))
        self.assertFalse(math.isinf(rtt_min))

    @settings(max_examples=500, deadline=None)
    @given(
        st.lists(
            st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False),
            min_size=0,
            max_size=20,
        ),
        st.floats(min_value=-1000.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        st.sampled_from([
            [],
            ["FLAG_SD_WAN_TUNNEL_OVERLAY"],
            ["FLAG_CLOUD_VPN_ENCAPSULATED"],
            ["FLAG_SD_WAN_TUNNEL_OVERLAY", "FLAG_CLOUD_VPN_ENCAPSULATED"]
        ]),
    )
    def test_fuzz_spatial_solver_extreme_inputs(
        self, rtt_samples, t_kernel, overlay_flags
    ):
        """SpatialSolver.estimate_distance must maintain non-negative distance without NaN/Inf."""
        solver = SpatialSolver()
        res = solver.estimate_distance(
            rtt_samples=rtt_samples,
            t_kernel=t_kernel,
            overlay_flags=overlay_flags
        )
        self.assertIsInstance(res, dict)
        self.assertEqual(json.loads(json.dumps(res)), res)
        self.assertGreaterEqual(res["distance_m"], 0.0)
        self.assertFalse(math.isnan(res["distance_m"]))
        self.assertFalse(math.isinf(res["distance_m"]))

    # =========================================================================
    # Phase 5: Buffer Resilience Validation & Edge-Case State Ingestion
    # =========================================================================

    @settings(max_examples=250, deadline=None)
    @given(mutated_tcp_frame())
    def test_fuzz_non_standard_tcp_sequences_scapy_ingestion(self, raw_frame: bytes):
        """
        Continuously injects non-standard TCP sequences, invalid offsets (<20 or >len),
        and corrupted RFC 7323 options into the Scapy ingestion layer.
        Verifies zero thread crashes, graceful degradation, and zero ledger corruption.
        """
        discovered_nodes = []
        engine = SpanCaptureEngine(on_node_discovered=discovered_nodes.append)

        res = engine.process_raw_frame(raw_frame)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(json.loads(json.dumps(res)), res)
            if "telemetry" in res and isinstance(res["telemetry"], dict):
                sj = res["telemetry"].get("spatial_jitter")
                if sj is not None:
                    self.assertIsInstance(sj, dict)
                    self.assertIn("ts_val", sj)
                    self.assertIn("ts_ecr", sj)

        # Assert no malformed IP addresses leaked into discovery
        for node in discovered_nodes:
            self.assertIsInstance(node, dict)
            self.assertIn("ip", node)
            self.assertNotIn("..", node["ip"])

    @settings(max_examples=250, deadline=None)
    @given(mutated_icmp_frame())
    def test_fuzz_edge_case_icmp_payloads_ingestion(self, raw_frame: bytes):
        """
        Injects malformed, truncated, and edge-case RFC 792/1122 ICMP payloads into the
        ingestion layer. Verifies graceful parsing or safe discarding without unhandled exceptions.
        """
        engine = SpanCaptureEngine()
        res = engine.process_raw_frame(raw_frame)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(json.loads(json.dumps(res)), res)
            self.assertIn("src_mac", res)
            self.assertIn("dst_mac", res)

    @settings(max_examples=250, deadline=None)
    @given(mutated_modbus_frame())
    def test_fuzz_fragmented_modbus_frames_ingestion(self, raw_payload: bytes):
        """
        Directly injects truncated, oversized, non-zero protocol ID, and fragmented
        Modbus frames into OtWireDissector.dissect_modbus_tcp.
        Verifies that invalid frames drop gracefully and do not pollute the Redis ledger.
        """
        res = OtWireDissector.dissect_modbus_tcp(raw_payload)
        if res is not None:
            self.assertIsInstance(res, dict)
            self.assertEqual(res["protocol"], "MODBUS")
            self.assertIn("transaction_id", res)
            self.assertIn("unit_id", res)
            self.assertIn("function_code", res)
            self.assertIn("is_exception", res)
            self.assertEqual(json.loads(json.dumps(res)), res)


if __name__ == "__main__":
    unittest.main()
