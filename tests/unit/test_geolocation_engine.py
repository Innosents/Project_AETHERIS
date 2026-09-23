"""
Unit test suite for GeolocationEnginePort, CivicLocationPort, and SpatialPathReasonerPort.
Validates AST boundary isolation, mathematical geodesics, ANSI/TIA-1057 dissection, and schema immutability.
"""
import ast
import os
import pytest
from aetheris.core.ports.geolocation_engine_port import (
    GeolocationEnginePort,
    CivicLocationPort,
    SpatialPathReasonerPort,
    PublicGeoMetadata,
    NormalizedCivicAddress,
    PhysicalVectorResult,
    SpatialPathSummary,
)
from aetheris.discovery.geolocation_engine import (
    PublicGeoIpResolver,
    LldpMedLocationDecoder,
    SpatialPathReasoner,
    GeolocationProtocolsLibrary,
)


def test_geolocation_engine_port_ast_boundary():
    """Verify geolocation_engine_port.py contains zero forbidden I/O imports."""
    port_path = os.path.join("aetheris", "core", "ports", "geolocation_engine_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"urllib", "requests", "socket", "scapy", "subprocess", "sqlite3", "redis"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_public_geoip_resolver_conformance_and_geodesics():
    """Verify GeolocationEnginePort protocol conformance, Haversine geodesics, and RTT delay calculation."""
    assert issubclass(PublicGeoIpResolver, GeolocationEnginePort)

    # Great-circle distance between SF (37.7749, -122.4194) and NYC (40.7128, -74.0060) ~ 4130 km
    dist = PublicGeoIpResolver.calculate_haversine_distance_km(37.7749, -122.4194, 40.7128, -74.0060)
    assert 4100.0 <= dist <= 4200.0

    # Minimum optical RTT across 4130 km in single-mode fiber with 1.5x inflation scalar
    # (2 * 4130 / 200860) * 1000 * 1.5 ~ 61.68 ms
    rtt_min = PublicGeoIpResolver.calculate_rtt_min_ms(dist, inflation_scalar=1.5)
    assert 60.0 <= rtt_min <= 65.0

    # Offline / Private IP resolution returns typed PublicGeoMetadata
    meta = PublicGeoIpResolver.resolve_ip("192.168.1.1")
    assert isinstance(meta, PublicGeoMetadata)
    assert meta.public_ip == "192.168.1.1"
    assert meta["city"] == "HQ Office"
    assert "city" in meta
    assert meta.get("country_code") == "US"


def test_lldp_med_location_decoder_civic_and_vector():
    """Verify CivicLocationPort conformance, civic address normalization, and tromboning/zone flags."""
    assert issubclass(LldpMedLocationDecoder, CivicLocationPort)

    # 1. Normalization
    raw_civic = {
        "building": "Bldg 4",
        "floor": "Floor 3",
        "room": "Server_MDF",
        "wall_jack": "Jack-42",
        "country": "US"
    }
    norm = LldpMedLocationDecoder.normalize_civic_address(raw_civic)
    assert isinstance(norm, NormalizedCivicAddress)
    assert norm.building == "Bldg 4"
    assert norm.floor == "3"
    assert norm.is_restricted is True
    assert norm["zone_type"] == "RESTRICTED"

    # 2. Intra-floor tromboning detection
    src_loc = {"building": "HQ", "floor": "2", "room": "Room 201"}
    dst_loc = {"building": "HQ", "floor": "2", "room": "Room 205"}
    vec_tromboning = LldpMedLocationDecoder.compute_physical_vector(
        src_civic=src_loc,
        dst_civic=dst_loc,
        latency_us=25.0  # > 10 us threshold for same-floor local switch flow
    )
    assert isinstance(vec_tromboning, PhysicalVectorResult)
    assert vec_tromboning.same_floor is True
    assert "FLAG_CROSS_FLOOR_TROMBONING" in vec_tromboning.flags
    assert vec_tromboning["same_building"] is True

    # 3. Zone perimeter boundary breach detection
    src_restricted = {"building": "HQ", "floor": "1", "room": "DataCenter_MDF"}
    dst_public = {"building": "HQ", "floor": "1", "room": "Visitor_Lobby"}
    vec_breach = LldpMedLocationDecoder.compute_physical_vector(
        src_civic=src_restricted,
        dst_civic=dst_public,
        latency_us=2.0
    )
    assert "FLAG_ZONE_BOUNDARY_VIOLATION" in vec_breach.flags


def test_spatial_path_reasoner_and_summary_immutability():
    """Verify SpatialPathReasoner returns typed SpatialPathSummary with frozen immutability."""
    assert issubclass(SpatialPathReasoner, SpatialPathReasonerPort)

    summary = SpatialPathReasoner.compute_spatial_path(
        node_id="node_1",
        node_meta={
            "label": "VoIP Phone 101",
            "ip": "192.168.1.101",
            "port": "GigabitEthernet1/0/12",
            "civic_location": {"room": "Office 301"}
        },
        all_nodes={"sw_1": {"type": "managed_switch", "label": "Edge-Switch-Bldg4"}},
        edges=[("node_1", "sw_1", {})],
        macro_geo={"city": "San Jose", "country_code": "US", "latitude": 37.3382, "longitude": -121.8863}
    )

    assert isinstance(summary, SpatialPathSummary)
    assert summary["accuracy_estimate_meters"] == 5.0
    assert any("Edge-Switch-Bldg4" in step for step in summary.spatial_path_trail)
    assert summary.is_virtual_overlay is False

    with pytest.raises(Exception):
        summary.is_virtual_overlay = True


def test_geolocation_protocols_library():
    """Verify GeolocationProtocolsLibrary maintains catalog of all 11 positioning standards."""
    protocols = GeolocationProtocolsLibrary.get_all_protocols()
    assert len(protocols) == 11

    lldp = GeolocationProtocolsLibrary.get_protocol_by_id("lldp_med")
    assert lldp is not None
    assert lldp["standard"] == "ANSI/TIA-1057 / IEEE 802.1AB"
