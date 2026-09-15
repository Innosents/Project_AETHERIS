"""
Unit Tests for SubnetSweeper Spatial Normalization Integration
Verifies that high-jitter Linux endpoints (up to 7ms scheduling delay)
are bounded by SpatialNormalizationEngine and do not explode to 1,000+ km.
"""

from unittest.mock import patch, MagicMock
from graphpath.cli.sweep import SubnetSweeper
from graphpath.core.spatial_normalizer import SpatialNormalizationEngine, SpatialEvidenceBound


def test_linux_high_jitter_bounded_by_normalizer():
    # Simulate a Linux server with 7ms scheduling jitter
    # 7ms unconstrained would equal ~720km in copper
    rtt_samples_us = [7000.0, 7100.0, 7050.0, 7200.0, 7010.0]
    archetype = "LINUX_SERVER"
    anchor_offset_us = 1101.2

    # Verify RTT pulse normalizer clamps within physical bounds
    rtt_bound = SpatialNormalizationEngine.normalize_rtt_pulse(
        rtt_samples_us=rtt_samples_us,
        archetype=archetype,
        anchor_offset_us=anchor_offset_us
    )
    assert rtt_bound.distance_estimate_m <= SpatialNormalizationEngine.IEEE_802_3_MAX_RUN_M
    assert rtt_bound.distance_estimate_m >= 0.5
    assert rtt_bound.constraint_type == "RTT_PULSE"

    # Multi-source fusion with switchport topology
    fdb_bound = SpatialNormalizationEngine.normalize_switchport_fdb(is_trunk=False, mac_density=1)
    fused = SpatialNormalizationEngine.fuse_evidence([fdb_bound, rtt_bound])

    # Fused distance must be realistic (< 100m) and NOT hundreds of kilometers
    assert 10.0 <= fused["distance_m"] <= 100.0
    assert fused["variance_m2"] > 0
    assert fused["confidence_pct"] >= 15.0


def test_subnet_sweeper_integration_with_normalizer():
    sweeper = SubnetSweeper(
        subnet_cidr="192.168.10.0/24",
        interface=None,
        prober_lead_m=2.0,
        burst_count=5,
        api_url=None
    )

    # Mock packet tap to return 7ms RTT pulses (simulating high softirq latency)
    mock_tap = MagicMock()
    mock_tap.execute_rtt_pulse_burst.return_value = [7000.0, 7050.0, 7020.0, 7100.0, 7010.0]
    sweeper.engine.packet_tap = mock_tap

    # Mock srp1 port scan to identify Linux host
    with patch("graphpath.cli.sweep.srp1") as mock_srp1:
        mock_resp = MagicMock()
        mock_resp.haslayer.return_value = True
        mock_resp.__getitem__.side_effect = lambda layer: MagicMock(ttl=64, flags=0x12)
        mock_srp1.return_value = mock_resp

        sweeper.fingerprint_and_probe_host(
            ip_addr="192.168.10.42",
            mac_addr="00:0c:29:ab:cd:ef"
        )

    # Verify edge stored in graph store
    node_id = "host_192_168_10_42"
    edge = sweeper.store.get_edge(sweeper.engine.switch_id, node_id)
    assert edge is not None

    # Assert distance is strictly bounded under 100m, NOT hundreds of kilometers
    assert edge["distance_m"] <= 100.0
    assert edge["distance_m"] >= 0.5
    assert edge["confidence_pct"] >= 15.0
