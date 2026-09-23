"""
Unit Test Suite for Anchor Subgraph Resolver & Topological Memory Transition.
Validates:
1. Deterministic canonical SHA-256 fingerprinting for Anchor Subgraph Hashing (ASH).
2. SQLite relational cluster schema and cascade constraints.
3. Strict Jaccard-weighted recognition threshold (N >= 3).
4. Sub-threshold rejection with linear confidence scaling.
5. Novel cluster registration and episodic recall count tracking.
6. Multi-cluster competitive best-match selection.
7. TelemetryLedger verified identity lookup and cluster state hydration.
8. DeviceIdentityProfileManager ledger fallback proxy integration.
9. JsonDipStorageAdapter deprecation and zero-disk-dependency isolation.
10. Orchestrator topological context extraction and evaluation.
"""

import time
import pytest
from pathlib import Path
from aetheris.core.telemetry_ledger import TelemetryLedger, ConvergenceRecord
from aetheris.core.anchor_resolver import AnchorSubgraphResolver
from aetheris.infrastructure.adapters.storage.json_dip_storage_adapter import JsonDipStorageAdapter
from aetheris.core.dip_manager import DeviceIdentityProfileManager


@pytest.fixture
def test_db_path(tmp_path):
    return str(tmp_path / "test_ash_ledger.db")


@pytest.fixture
def ledger(test_db_path):
    return TelemetryLedger(db_path=test_db_path)


@pytest.fixture
def resolver(ledger):
    return AnchorSubgraphResolver(ledger)


def test_compute_anchor_fingerprint_invariance(resolver):
    """Asserts deterministic SHA-256 fingerprinting regardless of order, case, or whitespace."""
    macs_1 = ["00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
    macs_2 = [" aa:bb:cc:dd:ee:ff ", "11:22:33:44:55:66", "00:1A:2B:3C:4D:5E"]

    fp1 = resolver.compute_anchor_fingerprint(macs_1)
    fp2 = resolver.compute_anchor_fingerprint(macs_2)

    assert fp1 == fp2
    assert len(fp1) == 16
    assert isinstance(fp1, str)
    assert all(c in "0123456789abcdef" for c in fp1)


def test_register_new_cluster(resolver, ledger):
    """Asserts novel cluster registration into SQLite network_clusters and cluster_anchors."""
    anchors = [
        {"mac": "00:1A:2B:01:02:03", "type": "GATEWAY", "ip": "192.168.1.1", "confidence": 1.0},
        {"mac": "00:1A:2B:04:05:06", "type": "STP_ROOT", "ip": "192.168.1.2", "confidence": 0.95},
        {"mac": "00:1A:2B:07:08:09", "type": "LLDP_CHASSIS", "ip": "192.168.1.3", "confidence": 0.90},
    ]

    cluster_id = resolver.register_new_cluster(
        label="Test-Subnet-01",
        environment_cidr="192.168.1.0/24",
        anchors=anchors,
        metadata={"site": "Facility-A", "vlan": 100}
    )

    assert cluster_id.startswith("NET-")
    assert len(cluster_id) == 20  # "NET-" + 16 chars

    # Verify cluster state via ledger
    state = ledger.fetch_cluster_state(cluster_id)
    assert state is not None
    assert state["cluster_id"] == cluster_id
    assert state["label"] == "Test-Subnet-01"
    assert state["environment_cidr"] == "192.168.1.0/24"
    assert state["recall_count"] == 1
    assert state["metadata"]["site"] == "Facility-A"
    assert len(state["anchors"]) == 3


def test_evaluate_environment_sub_threshold(resolver):
    """Asserts candidate sets matching < 3 anchors are rejected with scaled confidence."""
    anchors = [
        {"mac": "10:00:00:00:00:01", "type": "GATEWAY", "ip": "10.0.0.1"},
        {"mac": "10:00:00:00:00:02", "type": "STP_ROOT", "ip": "10.0.0.2"},
        {"mac": "10:00:00:00:00:03", "type": "LLDP_CHASSIS", "ip": "10.0.0.3"},
        {"mac": "10:00:00:00:00:04", "type": "STATIC_SWITCH", "ip": "10.0.0.4"},
    ]
    resolver.register_new_cluster("Prod-Core", "10.0.0.0/24", anchors)

    # Candidate with only 2 matches (below threshold 3)
    candidates = [
        {"mac": "10:00:00:00:00:01", "type": "GATEWAY"},
        {"mac": "10:00:00:00:00:02", "type": "STP_ROOT"},
        {"mac": "99:99:99:99:99:99", "type": "RANDOM_NODE"},
    ]

    matched_id, conf, matched_macs = resolver.evaluate_environment(candidates, cidr_hint="10.0.0.0/24")

    assert matched_id is None
    assert len(matched_macs) == 2
    assert "10:00:00:00:00:01" in matched_macs
    assert "10:00:00:00:00:02" in matched_macs
    # Confidence: (2 / 3) * 0.50 ~ 0.3333
    assert abs(conf - (2.0 / 3.0 * 0.50)) < 1e-4


def test_evaluate_environment_threshold_met_and_recall_updated(resolver, ledger):
    """Asserts candidate matching >= 3 anchors yields cluster_id, confidence, and bumps recall."""
    anchors = [
        {"mac": "20:00:00:00:00:01", "type": "GATEWAY", "ip": "172.16.0.1"},
        {"mac": "20:00:00:00:00:02", "type": "STP_ROOT", "ip": "172.16.0.2"},
        {"mac": "20:00:00:00:00:03", "type": "LLDP_CHASSIS", "ip": "172.16.0.3"},
        {"mac": "20:00:00:00:00:04", "type": "STATIC_SWITCH", "ip": "172.16.0.4"},
    ]
    cluster_id = resolver.register_new_cluster("Datacenter-VLAN20", "172.16.0.0/24", anchors)

    candidates_3 = [
        {"mac": "20:00:00:00:00:01"},
        {"mac": "20:00:00:00:00:02"},
        {"mac": "20:00:00:00:00:03"},
    ]
    matched_id, conf, matched_macs = resolver.evaluate_environment(candidates_3)

    assert matched_id == cluster_id
    assert len(matched_macs) == 3
    # min(1.0, 0.60 + 3 * 0.10) = 0.90
    assert abs(conf - 0.90) < 1e-4

    state = ledger.fetch_cluster_state(cluster_id)
    assert state["recall_count"] == 2

    # 4 matches -> confidence capped at 1.0
    candidates_4 = [
        {"mac": "20:00:00:00:00:01"},
        {"mac": "20:00:00:00:00:02"},
        {"mac": "20:00:00:00:00:03"},
        {"mac": "20:00:00:00:00:04"},
    ]
    matched_id, conf, matched_macs = resolver.evaluate_environment(candidates_4)
    assert matched_id == cluster_id
    assert conf == 1.0
    assert len(matched_macs) == 4

    state = ledger.fetch_cluster_state(cluster_id)
    assert state["recall_count"] == 3


def test_evaluate_environment_empty_and_null_candidates(resolver):
    """Asserts graceful handling of empty or blank candidate sets."""
    assert resolver.evaluate_environment([]) == (None, 0.0, [])
    assert resolver.evaluate_environment([{"mac": ""}, {"type": "GATEWAY"}]) == (None, 0.0, [])


def test_evaluate_environment_competitive_cluster_selection(resolver):
    """Asserts candidate matches the cluster with maximum anchor intersection."""
    c1_anchors = [
        {"mac": "30:00:00:00:00:01"},
        {"mac": "30:00:00:00:00:02"},
        {"mac": "30:00:00:00:00:03"},
        {"mac": "COMMON:00:00:01"},
    ]
    c2_anchors = [
        {"mac": "40:00:00:00:00:01"},
        {"mac": "40:00:00:00:00:02"},
        {"mac": "40:00:00:00:00:03"},
        {"mac": "40:00:00:00:00:04"},
        {"mac": "COMMON:00:00:01"},
    ]

    c1_id = resolver.register_new_cluster("Cluster-1", "10.1.0.0/24", c1_anchors)
    c2_id = resolver.register_new_cluster("Cluster-2", "10.2.0.0/24", c2_anchors)

    candidates = [
        {"mac": "COMMON:00:00:01"},
        {"mac": "40:00:00:00:00:01"},
        {"mac": "40:00:00:00:00:02"},
        {"mac": "40:00:00:00:00:03"},
    ]

    matched_id, conf, matched_macs = resolver.evaluate_environment(candidates)
    assert matched_id == c2_id
    assert len(matched_macs) == 4


def test_telemetry_ledger_verified_identity(ledger):
    """Asserts get_verified_identity interrogates convergence_ledger and cluster_anchors."""
    test_mac = "00:50:56:FE:ED:01"
    assert ledger.get_verified_identity(test_mac) is None

    # Insert convergence record
    rec = ConvergenceRecord(
        timestamp=time.time(),
        mac=test_mac,
        oui="005056",
        ip="192.168.50.100",
        archetype="INDUSTRIAL_PLC",
        min_rtt_us=450.0,
        jitter_us=8.0,
        converged_distance_m=12.0,
        converged_kernel_us=400.0,
        variance_m2=1.5,
        confidence_pct=92.0
    )
    ledger.record_convergence(rec)

    identity = ledger.get_verified_identity(test_mac)
    assert identity is not None
    assert identity["mac"] == test_mac
    assert identity["ip"] == "192.168.50.100"
    assert identity["archetype"] == "INDUSTRIAL_PLC"
    assert identity["confidence_pct"] == 92.0

    # Also verify fallback to cluster_anchors if convergence_ledger lacks entry
    anchor_mac = "AA:BB:CC:11:22:33"
    assert ledger.get_verified_identity(anchor_mac) is None

    resolver = AnchorSubgraphResolver(ledger)
    resolver.register_new_cluster("OT-Cell", "192.168.60.0/24", [
        {"mac": anchor_mac, "type": "GATEWAY", "ip": "192.168.60.1", "confidence": 1.0}
    ])

    anchor_ident = ledger.get_verified_identity(anchor_mac)
    assert anchor_ident is not None
    assert anchor_ident["mac"] == anchor_mac
    assert anchor_ident["ip"] == "192.168.60.1"
    assert anchor_ident["dev_type"] == "GATEWAY"


def test_json_dip_storage_adapter_deprecation(tmp_path):
    """Asserts JsonDipStorageAdapter load_profiles does not read disk and returns empty dict."""
    dummy_file = tmp_path / "device_identity_profiles.json"
    dummy_file.write_text('{"AA:BB:CC:DD:EE:FF": {"mac": "AA:BB:CC:DD:EE:FF"}}', encoding="utf-8")

    adapter = JsonDipStorageAdapter(storage_path=str(dummy_file))
    loaded = adapter.load_profiles()
    assert loaded == {}


def test_dip_manager_get_profile_by_mac_fallback(ledger):
    """Asserts DeviceIdentityProfileManager lookup queries ledger when cache misses."""
    test_mac = "00:0C:29:DE:AD:01"
    ledger.record_convergence(ConvergenceRecord(
        timestamp=time.time(),
        mac=test_mac,
        oui="000C29",
        ip="10.10.10.55",
        archetype="PLC_CONTROLLER",
        min_rtt_us=500.0,
        jitter_us=5.0,
        converged_distance_m=10.0,
        converged_kernel_us=490.0,
        variance_m2=2.0,
        confidence_pct=95.0
    ))

    # Initialize DIP manager with explicit ledger
    mgr = DeviceIdentityProfileManager(ledger=ledger)
    record = mgr.get_profile_by_mac(test_mac)
    assert record is not None
    assert record["mac"] == test_mac

    # Lookup should succeed and hydrate profile
    profile = mgr.lookup(test_mac)
    assert profile is not None
    assert profile.mac == test_mac
    assert profile.ip == "10.10.10.55"
    assert profile.confidence >= 0.80


def test_orchestrator_evaluate_topological_context(ledger, monkeypatch):
    """Asserts AetherisOrchestrator extracts candidates and evaluates ASH."""
    from aetheris.core.orchestrator import AetherisOrchestrator

    # Mock hardware / transport bindings so orchestrator can initialize in unit sandbox
    monkeypatch.setattr("aetheris.infrastructure.adapters.chassis_probe.ChassisIntelligenceProbe.__init__", lambda self, *args, **kwargs: None)
    monkeypatch.setattr("aetheris.infrastructure.adapters.memurai_bus.MemuraiEventBus.__init__", lambda self, *args, **kwargs: None)
    monkeypatch.setattr("aetheris.core.agent.SovereignAgent.__init__", lambda self, *args, **kwargs: None)

    orch = AetherisOrchestrator(interface="dummy0", ledger=ledger)

    # 1. First sweep: registers a novel cluster
    cluster_id, conf, matched, priors = orch.evaluate_topological_context(
        subnet="192.168.100.0/24",
        default_gw_mac="00:11:22:33:44:55",
        gw_ip="192.168.100.1",
        l2_chassis_beacons=[
            {"chassis_id": "00:11:22:33:44:56"},
            {"chassis_id": "00:11:22:33:44:57"},
        ]
    )
    assert cluster_id.startswith("NET-")
    assert priors is not None
    assert len(priors["anchors"]) == 3

    # 2. Subsequent sweep with identical anchors: must recall historical cluster
    matched_id, conf_match, matched_macs, matched_priors = orch.evaluate_topological_context(
        subnet="192.168.100.0/24",
        default_gw_mac="00:11:22:33:44:55",
        gw_ip="192.168.100.1",
        l2_chassis_beacons=[
            {"chassis_id": "00:11:22:33:44:56"},
            {"chassis_id": "00:11:22:33:44:57"},
        ]
    )
    assert matched_id == cluster_id
    assert conf_match >= 0.90
    assert len(matched_macs) == 3
