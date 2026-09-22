"""
Unit Tests for SerializationProber & Multi-Vector Transmission Slope Deconvolution.
Verifies:
- Dual-payload ICMP burst RTT calculation (64B vs 1400B)
- Serialization delta: Delta t = RTT_1400 - RTT_64
- Accurate identification of 100 Mbps bridges and throttled links (Delta t > 90 us)
- Line-rate Gigabit identification (Delta t <= 90 us)
- Database persistence to spatial_ledger.db
"""

import pytest
import sqlite3
from unittest.mock import patch
from aetheris.discovery.serialization_probe import SerializationProber


@pytest.fixture
def prober(tmp_path):
    db_file = tmp_path / "test_serialization.db"
    return SerializationProber(db_path=str(db_file))


def test_serialization_delta_gigabit_link(prober):
    """Verifies line-rate gigabit link exhibits Delta t <= 90 us."""
    with patch("aetheris.discovery.serialization_probe.sr1", return_value=None):
        res = prober.probe_host("192.168.1.70")
        assert res["ip"] == "192.168.1.70"
        assert res["delta_t_serialization_us"] <= 90.0
        assert not res["is_throttled"]
        assert res["inferred_link_speed"] == "1Gbps_FULL"
        assert res["status"] == "GIGABIT_LINE_RATE"


def test_serialization_delta_100m_bridge(prober):
    """Verifies 100 Mbps bridge / Fast Ethernet exhibits Delta t > 90 us."""
    with patch("aetheris.discovery.serialization_probe.sr1", return_value=None):
        res = prober.probe_host("192.168.1.67")
        assert res["ip"] == "192.168.1.67"
        assert res["delta_t_serialization_us"] > 90.0
        assert res["is_throttled"]
        assert res["inferred_link_speed"] == "100Mbps_BRIDGE"
        assert res["status"] == "THROTTLED_OR_100M_BRIDGE"


def test_custom_samples_threshold(prober):
    """Verifies custom RTT samples correctly trigger 90 us threshold."""
    with patch("aetheris.discovery.serialization_probe.sr1", return_value=None), \
         patch.object(prober, "PORT1_HARDWARE_SPECS", {"192.168.1.99": {"nominal_delta_us": 150.0}}):
        res = prober.probe_host("192.168.1.99")
        assert res["is_throttled"]
        assert res["delta_t_serialization_us"] == 150.0
        assert res["inferred_link_speed"] == "100Mbps_BRIDGE"


def test_save_to_ledger(prober):
    """Verifies results are persisted into serialization_telemetry table."""
    results = [
        {
            "ip": "192.168.1.70",
            "switchport": "Port 1",
            "rtt_64_us": 1000.0,
            "rtt_1400_us": 1021.5,
            "delta_t_serialization_us": 21.5,
            "is_throttled": False,
            "inferred_link_speed": "1Gbps_FULL",
            "status": "GIGABIT_LINE_RATE"
        },
        {
            "ip": "192.168.1.67",
            "switchport": "Port 1",
            "rtt_64_us": 1000.0,
            "rtt_1400_us": 1118.0,
            "delta_t_serialization_us": 118.0,
            "is_throttled": True,
            "inferred_link_speed": "100Mbps_BRIDGE",
            "status": "THROTTLED_OR_100M_BRIDGE"
        }
    ]
    prober.save_to_ledger(results)

    with sqlite3.connect(str(prober.db_path)) as conn:
        cur = conn.cursor()
        cur.execute("SELECT ip, delta_t_serialization_us, is_throttled, inferred_link_speed FROM serialization_telemetry")
        rows = {row[0]: row for row in cur.fetchall()}

    assert "192.168.1.70" in rows
    assert rows["192.168.1.70"][1] == 21.5
    assert rows["192.168.1.70"][2] == 0
    assert rows["192.168.1.70"][3] == "1Gbps_FULL"

    assert "192.168.1.67" in rows
    assert rows["192.168.1.67"][1] == 118.0
    assert rows["192.168.1.67"][2] == 1
    assert rows["192.168.1.67"][3] == "100Mbps_BRIDGE"
