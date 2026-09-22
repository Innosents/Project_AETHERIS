"""
Unit tests for DiscoveryEnginePort, NetworkScannerPort, and decoupled DiscoveryEngine.
Validates protocol conformance, mock scanner injection, scope guard filtering, and graph registration.
"""

from unittest.mock import MagicMock
import pytest

from aetheris.core.discovery_engine import DiscoveryEngine
from aetheris.core.ports.discovery_engine_port import (
    DiscoveredDeviceNode,
    DiscoveryEnginePort,
    DiscoveryRunSummary,
    DiscoverySweepConfig,
    NetworkScannerPort,
    PortScanSummary,
)
from aetheris.infrastructure.adapters.discovery.network_scanner_adapter import NetworkScannerAdapter


class MockNetworkScanner(NetworkScannerPort):
    """Mock implementation of NetworkScannerPort for offline isolated unit testing."""

    def __init__(self):
        self.icmp_hosts = ["192.168.1.10", "192.168.1.20"]
        self.arp_results = [
            {"ip": "192.168.1.10", "mac": "00:0C:29:11:22:33"},
            {"ip": "192.168.1.20", "mac": "B8:27:EB:AA:BB:CC"},
        ]

    def icmp_sweep(self, target_ips):
        return [ip for ip in target_ips if ip in self.icmp_hosts]

    def arp_scan(self, network_cidr):
        return self.arp_results

    def scan_ports(self, ip, ports=None):
        if ip == "192.168.1.10":
            return [22, 80], "COMPLETED"
        return [80], "COMPLETED"

    def grab_banner(self, ip, port, timeout=1.0):
        if port == 22:
            return "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        return "HTTP/1.1 200 OK\r\nServer: nginx"

    def fingerprint_device(self, ip, mac, open_ports, banners, services):
        return {
            "ip": ip,
            "mac": mac,
            "vendor": "VMware, Inc." if mac.startswith("00:0C:29") else "Raspberry Pi",
            "type": "server" if mac.startswith("00:0C:29") else "iot",
            "model": "VMware Virtual Machine" if mac.startswith("00:0C:29") else "Raspberry Pi 4",
        }

    def get_common_ports(self):
        return [22, 80, 443]


def test_discovery_engine_port_protocol_conformance():
    """Verify DiscoveryEngine conforms to DiscoveryEnginePort protocol."""
    assert issubclass(DiscoveryEngine, DiscoveryEnginePort)
    mock_graph = MagicMock()
    engine = DiscoveryEngine(graph=mock_graph, scanner=MockNetworkScanner())
    assert isinstance(engine, DiscoveryEnginePort)


def test_network_scanner_port_protocol_conformance():
    """Verify NetworkScannerAdapter conforms to NetworkScannerPort protocol."""
    assert issubclass(NetworkScannerAdapter, NetworkScannerPort)
    adapter = NetworkScannerAdapter()
    assert isinstance(adapter, NetworkScannerPort)


def test_pydantic_discovery_models():
    """Verify Pydantic models for configuration, node discovery, and summaries."""
    cfg = DiscoverySweepConfig(network_cidr="10.0.0.0/24", timeout=5.0)
    assert cfg.network_cidr == "10.0.0.0/24"
    assert cfg["network_cidr"] == "10.0.0.0/24"

    node = DiscoveredDeviceNode(
        ip="10.0.0.15",
        mac="00:11:22:33:44:55",
        vendor="Cisco Systems",
        type="switch",
        open_ports=[22, 80]
    )
    assert node.ip == "10.0.0.15"
    assert node["vendor"] == "Cisco Systems"
    assert 22 in node.open_ports

    summary = DiscoveryRunSummary(
        network_cidr="10.0.0.0/24",
        total_scanned=254,
        active_hosts=12,
        nodes_registered=12,
        duration_seconds=1.234
    )
    assert summary.active_hosts == 12
    assert summary["nodes_registered"] == 12


def test_discovery_engine_sweep_with_injected_scanner():
    """Verify DiscoveryEngine.run_basic_sweep with injected MockNetworkScanner."""
    mock_graph = MagicMock()
    mock_batch = MagicMock()
    mock_graph.batch_transaction.return_value.__enter__.return_value = mock_batch

    scanner = MockNetworkScanner()
    engine = DiscoveryEngine(graph=mock_graph, scanner=scanner)

    summary = engine.run_basic_sweep(network_cidr="192.168.1.0/24")

    assert summary is not None
    assert isinstance(summary, DiscoveryRunSummary)
    assert summary.network_cidr == "192.168.1.0/24"
    assert summary.active_hosts == 2
    assert summary.nodes_registered >= 2

    # Verify graph node and edge additions occurred
    assert mock_graph.add_node.called
    assert mock_graph.add_edge.called

