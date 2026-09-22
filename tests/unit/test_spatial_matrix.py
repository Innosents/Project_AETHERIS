"""
Unit tests for AETHERIS-STEP-06: Spatial Matrix Injection.
Validates zero-lock sharded LRU lookaside civic cache, LLDP-MED civic vector integration,
FLAG_CROSS_FLOOR_TROMBONING, and FLAG_ZONE_BOUNDARY_VIOLATION.
"""

import json
import threading
import pytest
from typing import Dict, Any

from aetheris.core.traffic_matrix import TrafficMatrixTracker, ShardedCivicCache
from aetheris.discovery.geolocation_engine import LldpMedLocationDecoder


class TestSpatialMatrixInjection:

    def test_sharded_civic_cache_concurrency_and_lru(self):
        """Validates multi-threaded zero-lock concurrency and LRU eviction across 32 shards."""
        cache = ShardedCivicCache(num_shards=32, max_entries_per_shard=10)
        errors = []

        def worker(worker_id: int):
            try:
                for i in range(50):
                    ip = f"10.{worker_id}.{i}.1"
                    civic = {
                        "building": f"Bldg-{worker_id}",
                        "floor": f"{i % 5 + 1}",
                        "room": f"Room-{i}"
                    }
                    cache.set(ip, civic)
                    res = cache.get(ip)
                    if res is None or res.get("building") != f"Bldg-{worker_id}":
                        errors.append(f"Cache miss or mismatch for {ip}")
            except Exception as ex:
                errors.append(str(ex))

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrency errors encountered: {errors}"
        # Assert each shard is bounded by max_entries_per_shard = 10
        assert cache.size() <= 32 * 10
        assert cache.size() > 0

        # Test clear
        cache.clear()
        assert cache.size() == 0

    def test_record_flow_with_explicit_civic_vectors(self):
        """Validates record_flow accepts explicit civic vectors and derives physical_vector."""
        tracker = TrafficMatrixTracker(max_flows=100)
        try:
            src_civic = {
                "building": "HQ-Bldg",
                "floor": "Floor 2",
                "room": "Room-201",
                "rack": "Rack-A"
            }
            dst_civic = {
                "building": "HQ-Bldg",
                "floor": "2",
                "room": "Room-204",
                "rack": "Rack-B"
            }

            tracker.record_flow(
                src_ip="192.168.1.50",
                dst_ip="192.168.1.60",
                port=80,
                proto="TCP",
                byte_count=2048,
                src_civic=src_civic,
                dst_civic=dst_civic,
                latency_us=3.5
            )

            spatial_flows = tracker.get_spatial_flows()
            assert len(spatial_flows) == 1
            flow = spatial_flows[0]

            pv = flow.get("physical_vector")
            assert pv is not None
            assert pv["same_building"] is True
            assert pv["same_floor"] is True
            assert pv["src_civic"]["floor"] == "2"
            assert pv["dst_civic"]["floor"] == "2"
            assert pv["latency_us"] == 3.5
            assert "FLAG_CROSS_FLOOR_TROMBONING" not in pv["flags"]

            # Verify cached
            assert tracker.get_civic_location("192.168.1.50")["room"] == "Room-201"
            assert tracker.get_civic_location("192.168.1.60")["room"] == "Room-204"
        finally:
            tracker.stop()

    def test_lookaside_cache_automatic_resolution(self):
        """Validates that flows automatically resolve civic endpoints from the LRU lookaside cache."""
        tracker = TrafficMatrixTracker(max_flows=100)
        try:
            # Pre-register host civic locations as if populated via periodic LLDP-MED beacons
            tracker.register_civic_location("10.10.1.100", {
                "building": "Plant-01",
                "floor": "FL-01",
                "room": "Control_Room"
            })
            tracker.register_civic_location("10.10.1.200", {
                "building": "Plant-01",
                "floor": "1",
                "room": "PLC_Cabinet_04"
            })

            # Record flow without passing civic args
            tracker.record_flow(
                src_ip="10.10.1.100",
                dst_ip="10.10.1.200",
                port=502,
                proto="TCP",
                byte_count=512,
                app_proto="MODBUS"
            )

            spatial_flows = tracker.get_spatial_flows()
            assert len(spatial_flows) == 1
            flow = spatial_flows[0]

            assert flow["src_civic"]["room"] == "Control_Room"
            assert flow["dst_civic"]["room"] == "PLC_Cabinet_04"
            assert flow["physical_vector"]["same_building"] is True
            assert flow["physical_vector"]["same_floor"] is True
        finally:
            tracker.stop()

    def test_flag_cross_floor_tromboning(self):
        """Validates FLAG_CROSS_FLOOR_TROMBONING triggers when intra-floor flow has core/WAN transit latency."""
        tracker = TrafficMatrixTracker(max_flows=100)
        try:
            tracker.register_civic_location("172.16.2.10", {"building": "Campus-A", "floor": "2", "room": "Office-201"})
            tracker.register_civic_location("172.16.2.20", {"building": "Campus-A", "floor": "2", "room": "Office-208"})

            # Flow 1: Low latency (2.5 us <= 10.0 us threshold) -> Local access switch, NO tromboning
            tracker.record_flow(
                src_ip="172.16.2.10",
                dst_ip="172.16.2.20",
                port=445,
                proto="TCP",
                byte_count=1024,
                latency_us=2.5
            )

            flagged = tracker.get_flagged_flows("FLAG_CROSS_FLOOR_TROMBONING")
            assert len(flagged) == 0

            # Flow 2: High latency (28.4 us > 10.0 us threshold) -> Core aggregation / WAN tromboning
            tracker.record_flow(
                src_ip="172.16.2.10",
                dst_ip="172.16.2.20",
                port=445,
                proto="TCP",
                byte_count=2048,
                latency_us=28.4
            )

            flagged = tracker.get_flagged_flows("FLAG_CROSS_FLOOR_TROMBONING")
            assert len(flagged) == 1
            assert "FLAG_CROSS_FLOOR_TROMBONING" in flagged[0]["spatial_flags"]

            # Flow 3: Different floors (Floor 1 vs Floor 2) with high latency -> Expected routing, NO tromboning flag
            tracker.register_civic_location("172.16.1.10", {"building": "Campus-A", "floor": "1", "room": "Office-101"})
            tracker.record_flow(
                src_ip="172.16.1.10",
                dst_ip="172.16.2.20",
                port=443,
                proto="TCP",
                byte_count=4096,
                latency_us=35.0
            )

            inter_floor_flagged = [
                f for f in tracker.get_flagged_flows("FLAG_CROSS_FLOOR_TROMBONING")
                if f["src_ip"] == "172.16.1.10"
            ]
            assert len(inter_floor_flagged) == 0
        finally:
            tracker.stop()

    def test_flag_zone_boundary_violation(self):
        """Validates FLAG_ZONE_BOUNDARY_VIOLATION triggers when restricted zone flows directly to public zone."""
        tracker = TrafficMatrixTracker(max_flows=100)
        try:
            # Restricted: Server_MDF, DataCenter, Vault, SCADA_Lab
            tracker.register_civic_location("10.0.1.5", {"building": "Main", "floor": "Basement", "room": "Server_MDF"})
            # Public: Lobby, Guest, Visitor, Cafeteria
            tracker.register_civic_location("10.0.10.50", {"building": "Main", "floor": "1", "room": "Lobby_Visitor_Kiosk"})
            # Standard: Office
            tracker.register_civic_location("10.0.2.15", {"building": "Main", "floor": "2", "room": "Finance_Office"})

            # Violation: Server_MDF (restricted) -> Lobby (public)
            tracker.record_flow(
                src_ip="10.0.1.5",
                dst_ip="10.0.10.50",
                port=8080,
                proto="TCP",
                byte_count=15000
            )

            breaches = tracker.get_flagged_flows("FLAG_ZONE_BOUNDARY_VIOLATION")
            assert len(breaches) == 1
            assert breaches[0]["src_ip"] == "10.0.1.5"
            assert breaches[0]["dst_ip"] == "10.0.10.50"
            assert "FLAG_ZONE_BOUNDARY_VIOLATION" in breaches[0]["spatial_flags"]

            # Non-Violation: Server_MDF (restricted) -> Finance_Office (standard)
            tracker.record_flow(
                src_ip="10.0.1.5",
                dst_ip="10.0.2.15",
                port=443,
                proto="TCP",
                byte_count=5000
            )
            standard_breaches = [
                f for f in tracker.get_flagged_flows("FLAG_ZONE_BOUNDARY_VIOLATION")
                if f["dst_ip"] == "10.0.2.15"
            ]
            assert len(standard_breaches) == 0

            # Non-Violation: Lobby (public) -> Lobby (public)
            tracker.register_civic_location("10.0.10.51", {"building": "Main", "floor": "1", "room": "Reception_Desk"})
            tracker.record_flow(
                src_ip="10.0.10.50",
                dst_ip="10.0.10.51",
                port=53,
                proto="UDP",
                byte_count=128
            )
            pub_breaches = [
                f for f in tracker.get_flagged_flows("FLAG_ZONE_BOUNDARY_VIOLATION")
                if f["src_ip"] == "10.0.10.50"
            ]
            assert len(pub_breaches) == 0
        finally:
            tracker.stop()

    def test_plain_text_and_json_invariance(self):
        """Enforces zero raw bytes, zero LaTeX formatting, and JSON round-trip invariance."""
        tracker = TrafficMatrixTracker(max_flows=100)
        try:
            tracker.register_civic_location("10.5.5.1", {"building": "DC-01", "floor": "1", "room": "Datacenter_A"})
            tracker.register_civic_location("10.5.5.2", {"building": "DC-01", "floor": "1", "room": "Cafeteria"})

            tracker.record_flow(
                src_ip="10.5.5.1",
                dst_ip="10.5.5.2",
                port=80,
                proto="TCP",
                byte_count=1024,
                latency_us=18.5
            )

            flows = tracker.get_spatial_flows()
            assert len(flows) == 1
            flow = flows[0]

            # JSON round-trip serialization test
            serialized = json.dumps(flow)
            deserialized = json.loads(serialized)
            assert deserialized == flow

            # Verify summary round-trip
            summary = tracker.get_summary()
            assert json.loads(json.dumps(summary)) == summary
            assert summary["civic_cache_size"] == 2
            assert summary["spatial_flows_count"] == 1
            assert summary["flagged_flows_count"] == 1

            # Assert zero LaTeX formatting characters in serialized flow
            for latex_token in ("$", "\\text", "\\mu", "\\Delta", "\\tau"):
                assert latex_token not in serialized, f"Forbidden LaTeX token '{latex_token}' found in payload"
        finally:
            tracker.stop()

    def test_backward_compatibility_record_flow_call(self):
        """Validates that existing 8-argument record_flow calls from mirror_engine operate without error."""
        tracker = TrafficMatrixTracker(max_flows=100)
        try:
            tracker.record_flow(
                src_ip="192.168.100.1",
                dst_ip="192.168.100.2",
                port=53,
                proto="UDP",
                byte_count=78,
                app_proto="DNS",
                domain="example.corp",
                hostname="dc01"
            )
            flow_key = ("192.168.100.1", "192.168.100.2", 53, "UDP")
            assert flow_key in tracker.flows
            entry = tracker.flows[flow_key]
            assert entry["packets"] == 1
            assert entry["bytes"] == 78
            assert entry["app_proto"] == "DNS"
            assert entry["domain"] == "example.corp"
            assert entry["hostname"] == "dc01"
            assert entry["src_civic"] is None
            assert entry["dst_civic"] is None
            assert entry["physical_vector"] is None
            assert entry["spatial_flags"] == []
        finally:
            tracker.stop()
