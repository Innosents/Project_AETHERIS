"""
Unit Tests for Deep Prober Expansion and DIP Enrichment Pipeline
Validates SSH banner extraction, HTTP title probing, DIP signature indexing,
and spatial confidence elevation for endpoints with baseline confidence < 96%.
"""

import socket
import threading
import tempfile
import os
import pytest
from unittest.mock import patch, MagicMock

from aetheris.discovery.deep_prober import SshProber, HttpTitleProber, RtspProber, ModbusProber
from aetheris.core.dip_manager import DeviceIdentityProfileManager
from aetheris.core.spatial_normalizer import SpatialNormalizationEngine, SpatialEvidenceBound
from aetheris.cli.sweep import SubnetSweeper


def test_ssh_prober_banner_parsing():
    """Validates banner parsing logic for standard Linux distros."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    def handle_client():
        try:
            client, _ = server_sock.accept()
            client.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7\r\n")
            client.close()
        except Exception:
            pass
        finally:
            server_sock.close()

    th = threading.Thread(target=handle_client)
    th.daemon = True
    th.start()

    res = SshProber.probe_ssh_banner("127.0.0.1", port=port, timeout=1.0)
    assert res.get("protocol") == "SSH"
    assert "OpenSSH_8.9p1" in res.get("banner", "")
    assert res.get("os_hint") == "Ubuntu Linux"
    assert res.get("type") == "server"


def test_http_title_prober():
    """Validates HTTP server header and title extraction."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    def handle_client():
        try:
            client, _ = server_sock.accept()
            _ = client.recv(1024)
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Apache/2.4.41 (Ubuntu)\r\n"
                b"Content-Type: text/html\r\n\r\n"
                b"<html><head><title>Edge Router Management Console</title></head><body>OK</body></html>"
            )
            client.sendall(resp)
            client.close()
        except Exception:
            pass
        finally:
            server_sock.close()

    th = threading.Thread(target=handle_client)
    th.daemon = True
    th.start()

    res = HttpTitleProber.probe_web_identity("127.0.0.1", ports=[port], timeout=1.0)
    assert res.get("protocol") == "HTTP"
    assert "Apache" in res.get("server", "")
    assert res.get("title") == "Edge Router Management Console"


def test_dip_manager_deep_signature_indexing():
    """Tests indexing and recall of verified deep hardware signatures."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_path = tf.name

    try:
        dip = DeviceIdentityProfileManager(storage_path=temp_path)
        dip.profiles = {}

        sig = {
            "protocol": "SSH",
            "banner": "SSH-2.0-OpenSSH_9.0 Debian-1",
            "os_hint": "Debian Linux",
            "type": "server"
        }

        # Commit signature
        profile = dip.record_deep_signature(
            ip="192.168.1.150",
            mac="00:11:22:33:44:55",
            deep_fingerprint=sig,
            archetype="LINUX_SERVER",
            env_cidr="192.168.1.0/24"
        )
        assert profile is not None
        assert profile["confidence"] >= 0.95
        assert profile["type"] == "server"

        # Lookup by exact MAC
        recalled_mac = dip.lookup_by_fingerprint(mac="00:11:22:33:44:55")
        assert recalled_mac is not None
        assert recalled_mac["mac"] == "00:11:22:33:44:55"

        # Lookup by deep banner signature
        recalled_sig = dip.lookup_by_fingerprint(deep_signature={"banner": "SSH-2.0-OpenSSH_9.0 Debian-1"})
        assert recalled_sig is not None
        assert recalled_sig["mac"] == "00:11:22:33:44:55"

        # Lookup by OUI
        recalled_oui = dip.lookup_by_fingerprint(oui="001122")
        assert recalled_oui is not None

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_confidence_elevation_below_96():
    """
    Simulates an endpoint where preliminary spatial fusion confidence is < 96%,
    and verifies that deep inspection and DIP enrichment boosts confidence to >= 96%.
    """
    sweeper = SubnetSweeper(subnet_cidr="192.168.1.0/24", prober_lead_m=2.0)
    mock_tap = MagicMock()
    mock_tap.execute_rtt_pulse_burst.return_value = [1150.0, 1151.0, 1149.5, 1152.0, 1150.5]
    sweeper.engine.packet_tap = mock_tap
    
    mock_ssh = {
        "protocol": "SSH",
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7",
        "os_hint": "Ubuntu Linux",
        "type": "server"
    }

    with patch("aetheris.discovery.deep_prober.SshProber.probe_ssh_banner", return_value=mock_ssh):
        # Execute probe on a mock host
        ip = "192.168.1.42"
        mac = "02:42:AC:11:00:02"
        sweeper.fingerprint_and_probe_host(ip, mac)

        node_id = f"host_{ip.replace('.', '_')}"
        edge_data = sweeper.store.get_edge(sweeper.engine.switch_id, node_id)
        assert edge_data is not None

        # Confidence should be elevated to >= 96.0% due to deep identity enrichment
        assert edge_data["confidence_pct"] >= 96.0
        assert edge_data["distance_m"] > 0.0
        assert edge_data["distance_m"] <= 100.0

