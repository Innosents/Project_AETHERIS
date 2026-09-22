import pytest
from aetheris.mcp.spatial_server import query_device_prior, get_ledger_stats, get_device_history

def test_mcp_tools_surface_ledger_data():
    stats = get_ledger_stats()
    assert "total_records" in stats
    assert "unique_macs" in stats

    priors = query_device_prior("BC7E8B", "LINUX_SERVER")
    assert priors["status"] in ("learned", "converged", "unlearned")

    history = get_device_history("192.168.1.70")
    assert isinstance(history, list)