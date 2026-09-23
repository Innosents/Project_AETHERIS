"""
Unit tests for AETHERIS Spatial Web Visualizer Bridge (FastAPI).
Validates root dashboard serving, /api/telemetry/ingest endpoint, and /api/telemetry/nodes cache.
"""

import pytest
from fastapi.testclient import TestClient
from aetheris.web.server import app, latest_telemetry, active_store


@pytest.fixture(autouse=True)
def reset_telemetry():
    latest_telemetry["nodes"] = []
    latest_telemetry["summary"] = {"total_nodes": 0, "avg_confidence": 0.0}
    active_store._graph.clear()


def test_root_dashboard_html():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "AETHERIS Physical L1/L2 Spatial Sweep Engine" in response.text
    assert "Discovered Nodes & Cable Runs" in response.text
    assert "cytoscape.min.js" in response.text
    assert '<div id="cy">' in response.text
    assert "Topology Key" in response.text


def test_telemetry_ingest_and_nodes_retrieval():
    client = TestClient(app)

    payload = {
        "node_id": "host_192_168_1_55",
        "node_props": {
            "ip": "192.168.1.55",
            "mac": "AC:BC:32:11:22:33",
            "archetype": "WINDOWS_HOST",
            "identity_label": "[MOBILE] Apple iPhone",
            "vendor": "Apple Inc.",
            "model": "Apple iPhone",
            "device_type": "mobile_ios",
            "confidence_pct": 98.0
        },
        "parent_switch_id": "sw_core",
        "distance_m": 12.4,
        "variance_m2": 0.04,
        "confidence_pct": 98.0,
        "is_anchor": False,
        "edge_type": "ETHERNET_LINK",
        "mcmc_kernel_turnaround_us": 1100.5
    }

    resp = client.post("/api/telemetry/ingest", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["node_id"] == "host_192_168_1_55"
    assert data["cached_nodes"] == 1

    # Verify query returns ingested telemetry
    nodes_resp = client.get("/api/telemetry/nodes")
    assert nodes_resp.status_code == 200
    nodes_data = nodes_resp.json()
    assert len(nodes_data["nodes"]) == 1
    node = nodes_data["nodes"][0]
    assert node["ip"] == "192.168.1.55"
    assert node["distance_m"] == 12.4
    assert node["confidence_pct"] == 98.0
    assert node["identity_label"] == "[MOBILE] Apple iPhone"
    assert node["edge_label"] == "12.4m (98%)"
    assert nodes_data["summary"]["total_nodes"] == 1
    assert nodes_data["summary"]["avg_confidence"] == 98.0


def test_empty_node_id_rejected_422():
    client = TestClient(app)
    resp = client.post("/api/telemetry/ingest", json={"node_id": ""})
    assert resp.status_code == 422
    assert resp.json()["status"] == "error"

    resp_spaces = client.post("/api/telemetry/ingest", json={"node_id": "   "})
    assert resp_spaces.status_code == 422

    resp_none = client.post("/api/telemetry/ingest", json={"node_id": None})
    assert resp_none.status_code == 422


def test_stream_telemetry_event_hierarchy_and_streaming():
    from unittest.mock import patch
    from aetheris.cli.sweep import SubnetSweeper

    sweeper = SubnetSweeper(subnet_cidr="192.168.1.0/24", api_url="http://127.0.0.1:8080/api/telemetry/ingest")

    with patch("requests.post") as mock_post:
        # 1. Port 1 non-trunk device should have parent Actiontec-Q6000
        sweeper._stream_telemetry_event(
            ip_addr="192.168.1.65",
            mac_addr="BC:7E:8B:0D:82:CA",
            dist=28.52,
            var=0.05,
            conf=99.5,
            is_anchor=False,
            is_wireless=False,
            fdb_entry={"switchport": "Port 1", "hostname": "SamsungTV"},
            gt_meta={"device_label": "Samsung Smart TV", "measured_length_m": 28.52}
        )
        assert mock_post.called
        call_args = mock_post.call_args[1]
        payload = call_args["json"]
        assert payload["node_id"] == "host_192_168_1_65"
        assert payload["parent_switch_id"] == "Actiontec-Q6000"
        assert payload["distance_m"] == 28.52
        assert payload["confidence_pct"] == 99.5

        # 2. Direct port device (Port 2) should have parent Gateway-Core
        mock_post.reset_mock()
        sweeper._stream_telemetry_event(
            ip_addr="192.168.1.86",
            mac_addr="24:4B:FE:96:1D:36",
            dist=27.0,
            var=0.05,
            conf=99.0,
            is_anchor=True,
            is_wireless=False,
            fdb_entry={"switchport": "Port 2", "hostname": "Workstation"},
            gt_meta={"device_label": "Primary Workstation", "measured_length_m": 27.0}
        )
        assert mock_post.called
        payload2 = mock_post.call_args[1]["json"]
        assert payload2["node_id"] == "host_192_168_1_86"
        assert payload2["parent_switch_id"] == "Gateway-Core"
        assert payload2["edge_type"] == "ETHERNET_ANCHOR"

        # 3. Suppress streaming for nodes flagged as is_probe_timeout
        mock_post.reset_mock()
        sweeper._stream_telemetry_event(
            ip_addr="192.168.1.99",
            mac_addr="00:11:22:33:44:55",
            dist=50.0,
            var=100.0,
            conf=0.0,
            is_anchor=False,
            is_wireless=False,
            is_probe_timeout=True
        )
        assert not mock_post.called


def test_topology_endpoint_elements_and_edge_label_formatting():
    client = TestClient(app)

    # 1. Ingest standard Ethernet link
    resp1 = client.post("/api/telemetry/ingest", json={
        "node_id": "host_192_168_1_55",
        "parent_switch_id": "Gateway-Core",
        "distance_m": 12.4,
        "confidence_pct": 98.0,
        "edge_type": "ETHERNET_LINK"
    })
    assert resp1.status_code == 200

    # 2. Ingest Wireless AirLink with distance
    resp2 = client.post("/api/telemetry/ingest", json={
        "node_id": "host_192_168_1_77",
        "parent_switch_id": "Gateway-Core",
        "distance_m": 5.2,
        "confidence_pct": 75.0,
        "edge_type": "WIRELESS_AIRLINK"
    })
    assert resp2.status_code == 200

    # 3. Ingest Wireless AirLink with 0m distance
    resp3 = client.post("/api/telemetry/ingest", json={
        "node_id": "host_192_168_1_88",
        "parent_switch_id": "Gateway-Core",
        "distance_m": 0.0,
        "confidence_pct": 0.0,
        "edge_type": "WIRELESS_AIRLINK"
    })
    assert resp3.status_code == 200

    # 4. Ingest Anchor link
    resp4 = client.post("/api/telemetry/ingest", json={
        "node_id": "host_192_168_1_86",
        "parent_switch_id": "Gateway-Core",
        "distance_m": 27.0,
        "confidence_pct": 99.0,
        "is_anchor": True,
        "edge_type": "ETHERNET_ANCHOR"
    })
    assert resp4.status_code == 200

    # Query /api/topology
    topo_resp = client.get("/api/topology")
    assert topo_resp.status_code == 200
    elements = topo_resp.json()
    assert isinstance(elements, list)
    assert len(elements) > 0

    edges = [el["data"] for el in elements if "source" in el["data"] and "target" in el["data"]]
    edge_map = {e["target"]: e for e in edges}

    # Verify edge labels
    assert edge_map["host_192_168_1_55"]["label"] == "12.4m (98%)"
    assert edge_map["host_192_168_1_77"]["label"] == "~5.2m (75%)"
    assert edge_map["host_192_168_1_88"]["label"] == "AirLink"
    assert edge_map["host_192_168_1_86"]["label"] == "27.0m (99%)"


def test_app_ingest_edge_label_formatting():
    from aetheris.web.app import app as ws_app, active_store as ws_store

    ws_store.nodes.clear()
    ws_store.edges.clear()
    client = TestClient(ws_app)

    # Ingest wired and wireless payloads into web.app
    r1 = client.post("/api/telemetry/ingest", json={
        "node_id": "host_wired",
        "parent_switch_id": "Gateway-Core",
        "distance_m": 15.0,
        "variance_m2": 0.01,
        "confidence_pct": 95.0,
        "edge_type": "ETHERNET_LINK"
    })
    assert r1.status_code == 200

    r2 = client.post("/api/telemetry/ingest", json={
        "node_id": "host_wireless",
        "parent_switch_id": "Gateway-Core",
        "distance_m": 7.5,
        "variance_m2": 0.1,
        "confidence_pct": 80.0,
        "edge_type": "WIRELESS_AIRLINK"
    })
    assert r2.status_code == 200

    topo = client.get("/api/graph").json()
    edges = {el["data"]["target"]: el["data"] for el in topo if "source" in el["data"]}
    assert edges["host_wired"]["label"] == "15.0m (95%)"
    assert edges["host_wireless"]["label"] == "~7.5m (80%)"


