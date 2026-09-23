"""
Unit test suite for LinuxCrawlerPort, LinuxEndpointCrawler, and pure kernel telemetry parsers.
Validates AST boundary isolation, protocol conformance, parsing accuracy, mocked SSH handshakes, and schema immutability.
"""
import ast
import os
import pytest
from unittest.mock import patch, MagicMock
from aetheris.core.ports.linux_crawler_port import (
    LinuxCrawlerPort,
    LinuxHostTelemetry,
    LinuxArpNeighbor,
    LinuxCrawlerRunSummary,
)
from aetheris.discovery.linux_crawler import (
    LinuxEndpointCrawler,
    run_linux_crawler,
)


def test_linux_crawler_port_ast_boundary():
    """Verify linux_crawler_port.py contains zero paramiko, socket, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "linux_crawler_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"paramiko", "socket", "subprocess", "scapy", "sqlite3", "redis", "urllib", "requests"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_linux_crawler_protocol_conformance():
    """Verify LinuxEndpointCrawler conforms to LinuxCrawlerPort Protocol."""
    crawler = LinuxEndpointCrawler()
    assert isinstance(crawler, LinuxCrawlerPort)


def test_parse_os_release_and_mem_info_pure():
    """Verify pure parsing of /etc/os-release and free -m outputs."""
    os_release_text = """
    NAME="Ubuntu"
    VERSION="22.04.3 LTS (Jammy Jellyfish)"
    ID=ubuntu
    PRETTY_NAME="Ubuntu 22.04.3 LTS"
    VERSION_ID="22.04"
    """
    os_name = LinuxEndpointCrawler.parse_os_release(os_release_text)
    assert os_name == "Ubuntu 22.04.3 LTS"

    # Fallback to raw uname
    uname_out = "Linux 5.15.0-89-generic x86_64"
    assert LinuxEndpointCrawler.parse_os_release(uname_out) == uname_out

    # Memory info
    mem_text = """
                   total        used        free      shared  buff/cache   available
    Mem:           31892        4520       18240         412        9132       26480
    Swap:           8192           0        8192
    """
    ram = LinuxEndpointCrawler.parse_mem_info(mem_text)
    assert ram == "31892"


def test_parse_listening_services_pure():
    """Verify pure parsing of ss -tulpn listening ports."""
    ss_output = """
    tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=842,fd=3))
    tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=1120,fd=6))
    tcp   LISTEN 0      511          0.0.0.0:443       0.0.0.0:*    users:(("nginx",pid=1120,fd=7))
    """
    services = LinuxEndpointCrawler.parse_listening_services(ss_output)
    assert services is not None
    assert "sshd:22" in services
    assert "nginx:80" in services
    assert "nginx:443" in services


def test_parse_arp_cache_pure():
    """Verify pure parsing of arp -a kernel neighbor cache."""
    arp_output = """
    gateway.local (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
    node2.local (192.168.1.50) at AA:BB:CC:DD:EE:FF [ether] on eth0
    incomplete.local (192.168.1.99) at 00:00:00:00:00:00 [ether] on eth0
    """
    neighbors = LinuxEndpointCrawler.parse_arp_cache(arp_output)
    assert len(neighbors) == 2

    n1 = neighbors[0]
    assert isinstance(n1, LinuxArpNeighbor)
    assert n1.ip == "192.168.1.1"
    assert n1.mac == "00:11:22:33:44:55"
    assert n1["ip"] == "192.168.1.1"


def test_crawl_linux_server_mocked_ssh():
    """Verify crawl_linux_server executes SSH command sequence and returns typed LinuxHostTelemetry."""
    mock_graph = MagicMock()
    crawler = LinuxEndpointCrawler(graph_store=mock_graph, timeout=0.5)

    with patch("paramiko.SSHClient") as mock_ssh_cls:
        mock_client = MagicMock()
        mock_ssh_cls.return_value = mock_client

        # Mock stdout for 4 commands: cat os-release, free -m, ss -tulpn, arp -a
        def mock_exec(cmd, timeout=None):
            stdout_mock = MagicMock()
            if "os-release" in cmd:
                stdout_mock.read.return_value = b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
            elif "free" in cmd:
                stdout_mock.read.return_value = b'Mem: 15980 2300 11000\n'
            elif "ss" in cmd:
                stdout_mock.read.return_value = b'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=456,fd=3))\n'
            elif "arp" in cmd:
                stdout_mock.read.return_value = b'? (10.0.0.1) at 00:50:56:AA:BB:CC [ether] on eth0\n'
            else:
                stdout_mock.read.return_value = b''
            return (MagicMock(), stdout_mock, MagicMock())

        mock_client.exec_command.side_effect = mock_exec

        res = crawler.crawl_linux_server("10.0.0.10", {"username": "root", "password": "secretpassword"})
        assert isinstance(res, LinuxHostTelemetry)
        assert res.ip == "10.0.0.10"
        assert res.os_version == "Debian GNU/Linux 12 (bookworm)"
        assert res["os_version"] == "Debian GNU/Linux 12 (bookworm)"
        assert res.total_ram_mb == "15980"
        assert "sshd:22" in res.running_services
        assert len(res.arp_neighbors) == 1

        # Verify graph store invocations
        assert mock_graph.add_node.called
        assert mock_graph.add_edge.called

        # Immutability check
        with pytest.raises(Exception):
            res.ip = "10.0.0.99"
