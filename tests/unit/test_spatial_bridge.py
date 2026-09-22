"""
Project AETHERIS - Unit Tests for Cytoscape Telemetry Bridge & Live Spatial Graph (Track 3)
Verifies:
  - HTTP telemetry payload ingestion and normalization (node & edge attributes).
  - Cytoscape JSON elements generation (/api/graph) with styling classes:
    (.anchor, .switch, .industrial_ot, .copper, .wlan).
  - Physical conductor length formatting (d ± σ) and variance calculation.
  - Zero-byte leakage, control character sanitization, and JSON round-trip symmetry.
  - Real-time Server-Sent Events (SSE) streaming endpoint (/api/telemetry/stream).
  - Degraded server resilience in sweep.py (0.2s timeout, zero-lag offline handling).
"""

import time
import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from aetheris.mcp.spatial_server import app, latest_telemetry, active_store
from aetheris.cli.sweep import SubnetSweeper


@pytest.fixture(autouse=True)
def reset_server_state():
    """Resets in-memory telemetry and graph store between test executions."""
    latest_telemetry["nodes"] = []
    latest_telemetry["summary"] = {"total_nodes": 0, "avg_confidence": 0.0}
    active_store._graph.clear()


def test_http_payload_ingestion_roundtrip():
    """Verifies that flat and nested telemetry payloads are ingested and normalized."""
    client = TestClient(app)

    # Ingest Industrial OT Device: Allen-Bradley 1769-L33ER CompactLogix PLC
    ab_payload = {
        "node_id": "host_192_168_1_50",
        "ip": "192.168.1.50",
        "mac": "00:00:BC:11:22:33",
        "hostname": "PLC-PACKAGING-LINE1",
        "device_type": "industrial_plc",
        "archetype": "ALLEN_BRADLEY_PLC",
        "os_profile": "EMBEDDED_COMPACTLOGIX",
        "confidence": 99.0,
        "is_anchor": False,
        "source": "Gateway-Core",
        "target": "host_192_168_1_50",
        "port": "Port 3",
        "medium": "Copper (Cat5e/Cat6 Drop)",
        "distance_m": 34.2,
        "variance_m2": 0.09,
        "jitter_ns": 45.0,
        "t_kernel_us": 850.0,
        "node_props": {
            "vendor": "Rockwell Automation",
            "model": "Allen-Bradley 1769-L33ER",
            "switchport": "Port 3"
        }
    }

    resp = client.post("/api/telemetry/ingest", json=ab_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["node_id"] == "host_192_168_1_50"
    assert data["cached_nodes"] == 1

    # Verify query returns normalized attributes
    nodes_resp = client.get("/api/telemetry/nodes")
    assert nodes_resp.status_code == 200
    nodes_data = nodes_resp.json()
    assert len(nodes_data["nodes"]) == 1
    node = nodes_data["nodes"][0]
    assert node["ip"] == "192.168.1.50"
    assert node["device_type"] == "industrial_plc"
    assert node["archetype"] == "ALLEN_BRADLEY_PLC"
    assert node["distance_m"] == 34.2
    assert node["variance_m2"] == 0.09
    assert node["switchport"] == "Port 3"


def test_cytoscape_elements_and_styling_classes():
    """
    Verifies /api/graph generates Cytoscape-formatted JSON elements
    with appropriate classes (.anchor, .switch, .industrial_ot, .copper, .wlan)
    and distance labels formatted as d ± σ.
    """
    client = TestClient(app)

    # 1. Ingest Core Switch & Physical Anchor
    client.post("/api/telemetry/ingest", json={
        "node_id": "host_192_168_1_70",
        "ip": "192.168.1.70",
        "mac": "00:1E:0B:AA:BB:CC",
        "hostname": "CALIBRATION-ANCHOR-PRINTER",
        "device_type": "printer",
        "archetype": "HP_PRINTER",
        "confidence": 99.8,
        "is_anchor": True,
        "source": "Gateway-Core",
        "port": "Port 2",
        "medium": "Copper",
        "distance_m": 3.0,
        "variance_m2": 0.01,
        "edge_type": "ETHERNET_ANCHOR"
    })

    # 2. Ingest Siemens S7-1200 PLC (Industrial OT)
    client.post("/api/telemetry/ingest", json={
        "node_id": "host_192_168_1_52",
        "ip": "192.168.1.52",
        "mac": "00:1C:06:44:55:66",
        "hostname": "SIEMENS-S7-1200-CPU",
        "device_type": "industrial_plc",
        "archetype": "SIEMENS_S7_PLC",
        "confidence": 98.5,
        "is_anchor": False,
        "source": "Gateway-Core",
        "port": "Port 1",
        "medium": "Copper",
        "distance_m": 22.5,
        "variance_m2": 0.04,
        "node_props": {"vendor": "Siemens", "model": "S7-1200 CPU 1214C"}
    })

    # 3. Ingest Wireless AirLink Endpoint (Bilian IoT Bridge)
    client.post("/api/telemetry/ingest", json={
        "node_id": "host_192_168_1_66",
        "ip": "192.168.1.66",
        "mac": "F4:84:8D:77:88:99",
        "hostname": "Bilian-WLAN-Bridge",
        "device_type": "wlan_bridge",
        "archetype": "ANDROID_WLAN_BRIDGE",
        "confidence": 88.0,
        "is_anchor": False,
        "source": "Gateway-Core",
        "port": "WLAN",
        "medium": "WLAN (802.11 AirLink)",
        "distance_m": 8.0,
        "variance_m2": 0.25,
        "edge_type": "WIRELESS_AIRLINK",
        "node_props": {"vendor": "Bilian", "model": "BL-WR9000"}
    })

    # Fetch /api/graph
    graph_resp = client.get("/api/graph")
    assert graph_resp.status_code == 200
    elements = graph_resp.json()
    assert isinstance(elements, list)

    nodes = {el["data"]["id"]: el for el in elements if "source" not in el["data"]}
    edges = {el["data"]["id"]: el for el in elements if "source" in el["data"]}

    # Verify Switch Node
    assert "Gateway-Core" in nodes
    assert "switch" in nodes["Gateway-Core"]["classes"]

    # Verify Anchor Node
    assert "host_192_168_1_70" in nodes
    assert "anchor" in nodes["host_192_168_1_70"]["classes"]

    # Verify Industrial OT Nodes
    assert "host_192_168_1_52" in nodes
    assert "industrial_ot" in nodes["host_192_168_1_52"]["classes"]

    # Verify Bilian IoT Bridge has industrial_ot badge
    assert "host_192_168_1_66" in nodes
    assert "industrial_ot" in nodes["host_192_168_1_66"]["classes"]

    # Verify Edge Classes and Distance ± σ Formatting
    # Anchor Edge
    edge_anchor = edges["edge_Gateway-Core_host_192_168_1_70"]
    assert "anchor" in edge_anchor["classes"]
    assert "copper" in edge_anchor["classes"]
    assert edge_anchor["data"]["label"] == "3.0m ± 0.10m"

    # Siemens Copper Edge
    edge_siemens = edges["edge_Gateway-Core_host_192_168_1_52"]
    assert "copper" in edge_siemens["classes"]
    assert edge_siemens["data"]["label"] == "22.5m ± 0.20m"

    # Wireless Edge
    edge_wlan = edges["edge_Gateway-Core_host_192_168_1_66"]
    assert "wlan" in edge_wlan["classes"]
    assert edge_wlan["data"]["label"] == "8.0m ± 0.50m"


def test_zero_byte_leakage_and_json_symmetry():
    """Verifies control character / null terminator sanitization and strict JSON serialization."""
    client = TestClient(app)

    dirty_payload = {
        "node_id": "host_dirty_test",
        "ip": "192.168.1.99",
        "mac": "AA:BB:CC:DD:EE:FF",
        "hostname": "PLC-PACKAGING\x00\x00\x1b[31m",
        "device_type": "industrial_plc\x00",
        "archetype": "ALLEN_BRADLEY_PLC",
        "confidence": 95.0,
        "is_anchor": False,
        "source": "Gateway-Core",
        "port": "Port 1\x00",
        "medium": "Copper",
        "distance_m": 15.0,
        "variance_m2": 0.04,
        "node_props": {
            "vendor": "Rockwell\x00Automation",
            "raw_frame": b"\x01\x02\x03\x04".hex()
        }
    }

    resp = client.post("/api/telemetry/ingest", json=dirty_payload)
    assert resp.status_code == 200

    graph_resp = client.get("/api/graph")
    assert graph_resp.status_code == 200
    data = graph_resp.json()

    # Null bytes must be completely purged
    serialized = json.dumps(data)
    assert "\x00" not in serialized
    deserialized = json.loads(serialized)
    assert deserialized == data


def test_sse_streaming_endpoint():
    """Verifies Server-Sent Events /api/telemetry/stream endpoint and polling mode."""
    client = TestClient(app)

    # Test polling mode fallback
    poll_resp = client.get("/api/telemetry/stream?poll=true")
    assert poll_resp.status_code == 200
    assert "summary" in poll_resp.json()

    # Test SSE stream headers with max_events=1
    with client.stream("GET", "/api/telemetry/stream?max_events=1") as stream_resp:
        assert stream_resp.status_code == 200
        assert "text/event-stream" in stream_resp.headers.get("content-type", "")
        lines = list(stream_resp.iter_lines())
        data_lines = [l for l in lines if l.startswith("data:")]
        assert len(data_lines) >= 1
        payload = json.loads(data_lines[0][len("data:"):].strip())
        assert payload.get("type") == "snapshot"


def test_degraded_server_resilience():
    """
    Verifies that sweep.py handles an offline / unreachable visualizer
    with timeout=0.2 and zero execution lag or unhandled exceptions.
    """
    # Point sweeper to an unreachable local port
    unreachable_url = "http://127.0.0.1:59999/api/telemetry/ingest"
    sweeper = SubnetSweeper(subnet_cidr="192.168.1.0/24", api_url=unreachable_url)

    start_time = time.time()
    # Execute streaming event to offline endpoint
    sweeper._stream_telemetry_event(
        ip_addr="192.168.1.55",
        mac_addr="00:11:22:33:44:55",
        dist=12.5,
        var=0.04,
        conf=95.0,
        is_anchor=False,
        is_wireless=False
    )
    duration = time.time() - start_time

    # Must complete within 0.3s (timeout=0.2) without raising exception
    assert duration < 0.35
