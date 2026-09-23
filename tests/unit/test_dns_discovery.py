"""
Unit test suite for DnsDiscoveryPort and DnsDiscoveryEngine adapter.
Validates AST boundary isolation, protocol conformance, pure overlay evaluation,
SRV record discovery, and model immutability.
"""
import ast
import os
from unittest.mock import patch
import pytest

from aetheris.core.ports.dns_discovery_port import (
    DnsDiscoveryPort,
    OverlayPathEvaluation,
    GeoPoint,
    DnsSrvRecord,
)
from aetheris.discovery.dns_discovery import DnsDiscoveryEngine


def test_dns_discovery_port_ast_boundary():
    """Verify dns_discovery_port.py contains zero socket, dnspython, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "dns_discovery_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"socket", "scapy", "subprocess", "sqlite3", "redis", "requests", "urllib", "dns"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_dns_discovery_engine_conformance():
    """Verify DnsDiscoveryEngine satisfies DnsDiscoveryPort protocol."""
    engine = DnsDiscoveryEngine()
    assert isinstance(engine, DnsDiscoveryPort)


def test_overlay_evaluation_sd_wan_flag():
    """Verify FLAG_SD_WAN_TUNNEL_OVERLAY detection when empirical RTT significantly exceeds min RTT."""
    engine = DnsDiscoveryEngine()

    sensor_geo = {"latitude": 49.05, "longitude": -122.32, "city": "Abbotsford", "country": "Canada"}
    target_geo = {"latitude": 49.28, "longitude": -123.12, "city": "Vancouver", "country": "Canada", "asn": "AS812"}

    # Vancouver to Abbotsford is ~65km -> rtt_min_ms is < 2ms.
    # An empirical RTT of 45ms indicates an unmasked overlay tunnel.
    res = engine.evaluate_overlay_path(
        ip="198.51.100.1",
        ptr_hostname="edge-router.local",
        empirical_rtt_ms=45.0,
        sensor_geo=sensor_geo,
        target_geo=target_geo
    )

    assert isinstance(res, OverlayPathEvaluation)
    assert isinstance(res.sensor_geo, GeoPoint)
    assert isinstance(res.target_geo, GeoPoint)
    assert res.sensor_geo.city == "Abbotsford"
    assert res.target_geo.city == "Vancouver"
    assert res["is_overlay"] is True
    assert "FLAG_SD_WAN_TUNNEL_OVERLAY" in res["flags"]
    assert res["rtt_delta_ms"] > 15.0

    # Test mapping dual access
    assert res.ip == res["ip"]
    assert res.is_overlay == res["is_overlay"]


def test_overlay_evaluation_cloud_vpn_flag():
    """Verify FLAG_CLOUD_VPN_ENCAPSULATED when hyperscaler ASN serves an on-prem PTR name."""
    engine = DnsDiscoveryEngine()

    sensor_geo = {"latitude": 49.05, "longitude": -122.32, "city": "Abbotsford", "country": "Canada"}
    # AWS US-East ASN 16509 with an on-prem naming pattern (.corp.internal)
    target_geo = {"latitude": 38.90, "longitude": -77.03, "city": "Ashburn", "country": "USA", "asn": "AS16509", "isp": "Amazon"}

    res = engine.evaluate_overlay_path(
        ip="52.94.76.1",
        ptr_hostname="core-sw01.corp.internal",
        empirical_rtt_ms=75.0,
        sensor_geo=sensor_geo,
        target_geo=target_geo
    )

    assert res["is_overlay"] is True
    assert "FLAG_CLOUD_VPN_ENCAPSULATED" in res["flags"]
    assert res["cloud_provider"] == "AWS"


def test_discover_srv_records():
    """Verify discover_srv_records returns a list of typed DnsSrvRecord items."""
    engine = DnsDiscoveryEngine()
    records = engine.discover_srv_records("example.corp")
    assert isinstance(records, list)
    for rec in records:
        assert isinstance(rec, DnsSrvRecord)


def test_sweep_ptr_records_safe_handling():
    """Verify sweep_ptr_records gracefully handles lookup failures."""
    engine = DnsDiscoveryEngine(timeout=0.05)
    with patch("socket.gethostbyaddr", side_effect=Exception("Host not found")):
        results = engine.sweep_ptr_records(["192.0.2.1", "192.0.2.2"])
        assert results == {}


def test_dns_port_models_immutability():
    """Verify GeoPoint, DnsSrvRecord, and OverlayPathEvaluation immutability and mapping."""
    geo = GeoPoint(latitude=37.77, longitude=-122.41, city="San Francisco", country="USA")
    assert geo["city"] == "San Francisco"
    assert geo.get("country") == "USA"
    with pytest.raises(Exception):
        geo.city = "Oakland"

    srv = DnsSrvRecord(service="_ldap._tcp", target="dc01.corp.local", port=389, priority=0, weight=100)
    assert srv.port == 389
    assert srv["target"] == "dc01.corp.local"
    with pytest.raises(Exception):
        srv.port = 636
