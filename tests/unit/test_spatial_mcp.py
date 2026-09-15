"""
Unit Tests for AETHERIS Spatial MCP Server
Validates MCP tools: query_device_prior, get_device_history, get_ledger_stats, and list_unique_endpoints.
"""

import time
import pytest
from unittest.mock import patch
from graphpath.core.telemetry_ledger import TelemetryLedger, ConvergenceRecord
from graphpath.mcp.spatial_server import (
    query_device_prior,
    get_device_history,
    get_ledger_stats,
    list_unique_endpoints
)


@pytest.fixture
def isolated_ledger(tmp_path):
    db_file = tmp_path / "mcp_test_ledger.db"
    test_ledger = TelemetryLedger(db_path=str(db_file))
    
    # Insert 3 test convergence records
    for i in range(3):
        test_ledger.record_convergence(ConvergenceRecord(
            timestamp=time.time() + i,
            mac=f"00:50:56:AB:CD:0{i}",
            oui="005056",
            ip=f"10.0.0.{i+10}",
            archetype="LINUX_SERVER",
            min_rtt_us=1100.0 + i,
            jitter_us=10.0,
            converged_distance_m=12.0 + i,
            converged_kernel_us=1100.0,
            variance_m2=15.0,
            confidence_pct=85.0
        ))
    return test_ledger


def test_mcp_query_device_prior(isolated_ledger):
    with patch("graphpath.mcp.spatial_server.ledger", isolated_ledger):
        # Learned prior
        res = query_device_prior(oui="00:50:56", archetype="LINUX_SERVER")
        assert res["status"] == "converged"
        assert res["oui"] == "005056"
        assert "median_kernel_turnaround_us" in res
        assert 1000.0 <= res["median_kernel_turnaround_us"] <= 1200.0

        # Unlearned prior
        res_unlearned = query_device_prior(oui="FFFFFF", archetype="UNKNOWN")
        assert res_unlearned["status"] == "unlearned"
        assert "default_priors" in res_unlearned


def test_mcp_get_device_history(isolated_ledger):
    with patch("graphpath.mcp.spatial_server.ledger", isolated_ledger):
        history_mac = get_device_history("00:50:56:AB:CD:00")
        assert len(history_mac) == 1
        assert history_mac[0]["ip"] == "10.0.0.10"
        assert history_mac[0]["converged_distance_m"] == 12.0

        history_ip = get_device_history("10.0.0.11")
        assert len(history_ip) == 1
        assert history_ip[0]["mac"] == "00:50:56:AB:CD:01"

        history_none = get_device_history("192.168.99.99")
        assert len(history_none) == 0


def test_mcp_get_ledger_stats(isolated_ledger):
    with patch("graphpath.mcp.spatial_server.ledger", isolated_ledger):
        stats = get_ledger_stats()
        assert stats["total_records"] == 3
        assert stats["unique_macs"] == 3
        assert stats["avg_confidence"] == 85.0
        assert stats["avg_variance"] == 15.0


def test_mcp_list_unique_endpoints(isolated_ledger):
    with patch("graphpath.mcp.spatial_server.ledger", isolated_ledger):
        endpoints = list_unique_endpoints()
        assert len(endpoints) == 3
        macs = {e["mac"] for e in endpoints}
        assert "00:50:56:AB:CD:00" in macs
        assert "00:50:56:AB:CD:01" in macs
        assert "00:50:56:AB:CD:02" in macs

