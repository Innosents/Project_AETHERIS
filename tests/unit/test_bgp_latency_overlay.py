"""
Unit tests for AETHERIS-STEP-07: Macroscopic BGP Latency Overlays & SD-WAN/VPN Unmasking.
Validates Haversine geodesic distance calculation, 1.5x BGP path inflation scalar,
FLAG_SD_WAN_TUNNEL_OVERLAY, FLAG_CLOUD_VPN_ENCAPSULATED, and virtual pseudo-node pruning.
"""

import json
import pytest
from typing import Dict, Any

from aetheris.discovery.geolocation_engine import PublicGeoIpResolver, SpatialPathReasoner
from aetheris.discovery.dns_discovery import DnsDiscoveryEngine
from aetheris.core.spatial_solver import SpatialSolver


class TestBgpLatencyOverlay:

    def test_haversine_geodesic_distance_precision(self):
        """Validates great-circle Haversine geodesic calculations against known geographic coordinates."""
        # San Francisco (37.7749, -122.4194) to New York City (40.7128, -74.0060)
        # Known great-circle distance is ~4,130 km
        d_sf_nyc = PublicGeoIpResolver.calculate_haversine_distance_km(
            37.7749, -122.4194, 40.7128, -74.0060
        )
        assert 4100.0 <= d_sf_nyc <= 4160.0

        # London (51.5074, -0.1278) to Tokyo (35.6762, 139.6503)
        # Known great-circle distance is ~9,560 km
        d_lon_tyo = PublicGeoIpResolver.calculate_haversine_distance_km(
            51.5074, -0.1278, 35.6762, 139.6503
        )
        assert 9500.0 <= d_lon_tyo <= 9620.0

        # Same location
        d_zero = PublicGeoIpResolver.calculate_haversine_distance_km(
            37.7749, -122.4194, 37.7749, -122.4194
        )
        assert d_zero == 0.0

    def test_rtt_min_with_bgp_inflation_scalar(self):
        """Validates that RTT_min incorporates v_fiber and empirical 1.5x BGP path inflation scalar."""
        distance_km = 1000.0
        # v_fiber = 200,860 km/s.
        # linear RTT = 2 * 1000 / 200860 * 1000 = ~9.957 ms
        # with 1.5x inflation scalar = 9.957 * 1.5 = ~14.936 ms
        rtt_min = PublicGeoIpResolver.calculate_rtt_min_ms(distance_km, inflation_scalar=1.5)
        assert 14.8 <= rtt_min <= 15.1

        # Zero distance
        assert PublicGeoIpResolver.calculate_rtt_min_ms(0.0) == 0.0

    def test_flag_sd_wan_tunnel_overlay_detection(self):
        """Validates that FLAG_SD_WAN_TUNNEL_OVERLAY triggers only when latency exceeds inflated RTT by > 15ms."""
        engine = DnsDiscoveryEngine()

        sensor_geo = {
            "latitude": 37.7749,
            "longitude": -122.4194,
            "city": "San Francisco",
            "country": "US"
        }
        target_geo = {
            "latitude": 40.7128,
            "longitude": -74.0060,
            "city": "New York",
            "country": "US",
            "asn": "AS7018 AT&T Services",
            "isp": "AT&T"
        }

        # Case A: Terrestrial path within inflation tolerance
        # SF-NYC is ~4130 km -> RTT_min_inflated ~61.7 ms.
        # Empirical RTT = 68.0 ms -> Delta = 6.3 ms (<= 15.0 ms threshold).
        # Valid terrestrial route, NO overlay flag.
        res_terrestrial = engine.evaluate_overlay_path(
            ip="12.34.56.78",
            ptr_hostname="edge-router.nyc.corp.com",
            empirical_rtt_ms=68.0,
            sensor_geo=sensor_geo,
            target_geo=target_geo
        )
        assert res_terrestrial["is_overlay"] is False
        assert "FLAG_SD_WAN_TUNNEL_OVERLAY" not in res_terrestrial["flags"]

        # Case B: SD-WAN Encapsulation / Tunnel backhaul
        # Empirical RTT = 85.0 ms -> Delta = 23.3 ms (> 15.0 ms threshold).
        # MUST trigger FLAG_SD_WAN_TUNNEL_OVERLAY.
        res_overlay = engine.evaluate_overlay_path(
            ip="12.34.56.78",
            ptr_hostname="edge-router.nyc.corp.com",
            empirical_rtt_ms=85.0,
            sensor_geo=sensor_geo,
            target_geo=target_geo
        )
        assert res_overlay["is_overlay"] is True
        assert "FLAG_SD_WAN_TUNNEL_OVERLAY" in res_overlay["flags"]
        assert res_overlay["rtt_delta_ms"] > 15.0

    def test_flag_cloud_vpn_encapsulated_detection(self):
        """Validates that FLAG_CLOUD_VPN_ENCAPSULATED triggers for hyperscaler ASNs with on-prem PTR names."""
        engine = DnsDiscoveryEngine()

        sensor_geo = {"latitude": 37.7749, "longitude": -122.4194}

        # Case A: AWS ASN (16509) with internal on-prem PTR name
        target_geo_aws = {
            "latitude": 38.9072,
            "longitude": -77.0369,
            "asn": "AS16509 AMAZON-02",
            "isp": "Amazon.com, Inc."
        }
        res_aws = engine.evaluate_overlay_path(
            ip="54.210.10.20",
            ptr_hostname="core-sw-01.corp.internal",
            empirical_rtt_ms=75.0,
            sensor_geo=sensor_geo,
            target_geo=target_geo_aws
        )
        assert "FLAG_CLOUD_VPN_ENCAPSULATED" in res_aws["flags"]
        assert res_aws["cloud_provider"] == "AWS"

        # Case B: Azure ASN (8075) with internal local name
        target_geo_azure = {
            "latitude": 47.6062,
            "longitude": -122.3321,
            "asn": "AS8075 MICROSOFT-CORP",
            "isp": "Microsoft Corporation"
        }
        res_azure = engine.evaluate_overlay_path(
            ip="20.40.50.60",
            ptr_hostname="plc-gateway.local",
            empirical_rtt_ms=30.0,
            sensor_geo=sensor_geo,
            target_geo=target_geo_azure
        )
        assert "FLAG_CLOUD_VPN_ENCAPSULATED" in res_azure["flags"]
        assert res_azure["cloud_provider"] == "Azure"

        # Case C: Public cloud service with standard cloud PTR name (NO false positive)
        res_public_aws = engine.evaluate_overlay_path(
            ip="54.210.10.21",
            ptr_hostname="ec2-54-210-10-21.compute-1.amazonaws.com",
            empirical_rtt_ms=45.0,
            sensor_geo=sensor_geo,
            target_geo=target_geo_aws
        )
        assert "FLAG_CLOUD_VPN_ENCAPSULATED" not in res_public_aws["flags"]

    def test_spatial_path_reasoner_prunes_copper_links(self):
        """Validates that SpatialPathReasoner prunes switchport/jack links and injects virtual pseudo-nodes."""
        macro_geo = {
            "city": "Dallas",
            "region": "Texas",
            "country_code": "US",
            "isp": "Enterprise WAN Uplink",
            "asn": "AS-Internal-Gateway"
        }
        all_nodes = {
            "sw-core-01": {"type": "switch", "label": "Core-Switch-01"}
        }
        edges = [("dev-node", "sw-core-01", {})]

        # Case A: Local physical node (NO overlay flags)
        node_meta_phys = {
            "label": "Local-Workstation",
            "ip": "10.0.1.50",
            "port": "Gi1/0/12",
            "civic_location": {"building": "Bldg-1", "floor": "2", "room": "204"}
        }
        res_phys = SpatialPathReasoner.compute_spatial_path(
            "dev-node", node_meta_phys, all_nodes, edges, macro_geo
        )
        trail_phys = res_phys["spatial_path_trail"]
        assert any("Switch Port: Gi1/0/12" in step for step in trail_phys)
        assert any("Wall Jack: Jack-Gi1/0/12" in step for step in trail_phys)
        assert any("Distribution Switch: Core-Switch-01" in step for step in trail_phys)
        assert res_phys["is_virtual_overlay"] is False

        # Case B: SD-WAN overlay node
        node_meta_sdwan = {
            "label": "Branch-Office-Gateway",
            "ip": "10.200.4.1",
            "port": "Gi1/0/24",
            "overlay_flags": ["FLAG_SD_WAN_TUNNEL_OVERLAY"],
            "asn": "AS64512",
            "rtt_delta_ms": 28.5
        }
        res_sdwan = SpatialPathReasoner.compute_spatial_path(
            "dev-node", node_meta_sdwan, all_nodes, edges, macro_geo
        )
        trail_sdwan = res_sdwan["spatial_path_trail"]
        # Pruned copper links
        assert not any("Switch Port" in step for step in trail_sdwan)
        assert not any("Wall Jack" in step for step in trail_sdwan)
        assert not any("Distribution Switch" in step for step in trail_sdwan)
        # Injected virtual pseudo-node
        assert any("Virtual Overlay: SD-WAN IPsec Tunnel" in step for step in trail_sdwan)
        assert res_sdwan["is_virtual_overlay"] is True
        assert res_sdwan["accuracy_estimate_meters"] is None

        # Case C: Cloud VPN encapsulated node
        node_meta_cloud = {
            "label": "Cloud-Database-Proxy",
            "ip": "10.100.2.15",
            "port": "Gi1/0/2",
            "overlay_flags": ["FLAG_CLOUD_VPN_ENCAPSULATED"],
            "cloud_provider": "AWS",
            "asn": "AS16509"
        }
        res_cloud = SpatialPathReasoner.compute_spatial_path(
            "dev-node", node_meta_cloud, all_nodes, edges, macro_geo
        )
        trail_cloud = res_cloud["spatial_path_trail"]
        assert not any("Switch Port" in step for step in trail_cloud)
        assert any("Virtual Overlay: Cloud VPN Encapsulated Gateway" in step for step in trail_cloud)
        assert res_cloud["is_virtual_overlay"] is True

    def test_spatial_solver_virtual_overlay_handling(self):
        """Validates that SpatialSolver bypasses 100m copper clamping when virtual overlay flags are present."""
        solver = SpatialSolver()

        # Regular physical node with 50 us RTT (clamps to 100m copper channel)
        res_phys = solver.estimate_distance(
            rtt_samples=[50.0],
            t_kernel=5.0,
            overlay_flags=[]
        )
        assert res_phys["is_virtual_overlay"] is False
        assert res_phys["distance_m"] <= 100.0

        # Virtual SD-WAN overlay node with 85,000 us (85 ms) RTT
        res_overlay = solver.estimate_distance(
            rtt_samples=[85000.0],
            t_kernel=5.0,
            overlay_flags=["FLAG_SD_WAN_TUNNEL_OVERLAY"]
        )
        assert res_overlay["is_virtual_overlay"] is True
        assert res_overlay["virtual_overlay_type"] == "SD_WAN_TUNNEL"
        assert "FLAG_SD_WAN_TUNNEL_OVERLAY" in res_overlay["overlay_flags"]
        # Distance bypasses 100m copper clamping
        assert res_overlay["distance_m"] > 100.0

    def test_plain_text_and_json_invariance(self):
        """Enforces zero raw bytes, zero LaTeX formatting, and JSON round-trip invariance across all emitted payloads."""
        engine = DnsDiscoveryEngine()
        sensor_geo = {"latitude": 37.7749, "longitude": -122.4194}
        target_geo = {
            "latitude": 40.7128,
            "longitude": -74.0060,
            "asn": "AS16509 AWS",
            "isp": "Amazon"
        }

        res = engine.evaluate_overlay_path(
            ip="10.200.1.1",
            ptr_hostname="switch-core.corp.internal",
            empirical_rtt_ms=88.4,
            sensor_geo=sensor_geo,
            target_geo=target_geo
        )

        serialized = json.dumps(res)
        deserialized = json.loads(serialized)
        assert deserialized == res

        # Assert zero LaTeX tokens in serialized JSON
        for forbidden in ("$", "\\text", "\\mu", "\\Delta", "\\tau"):
            assert forbidden not in serialized, f"Forbidden LaTeX token '{forbidden}' detected in overlay payload"
