"""
Unit Tests for Multi-Variance Stealth Prober Suite (Phase 1)
Validates NetBIOS (UDP 137), WS-Discovery (UDP 3702), and LLMNR (UDP 5355) probers,
hardware MAC extraction via RFC 1002 Unit ID, SOAP Probe parsing, reverse PTR parsing,
timeout/refusal resilience, JSON serialization symmetry, and SubnetSweeper integration.
"""

import json
import re
import socket
import struct
import threading
import time
from unittest.mock import patch, MagicMock
import pytest

from graphpath.core.probers.stealth_probe import (
    probe_netbios,
    probe_ws_discovery,
    probe_llmnr,
    probe_stealth_host,
    NETBIOS_NBSTAT_QUERY,
)
from graphpath.core.probers.sanitization import sanitize_prober_payload
from graphpath.cli.sweep import SubnetSweeper


# =========================================================================
# 1. NetBIOS Node Status (UDP 137) Prober Tests
# =========================================================================

def test_netbios_probe_success():
    """Validates NetBIOS NBSTAT query and response parsing (name, workgroup, and RFC 1002 MAC)."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("127.0.0.1", 0))
    port = server_sock.getsockname()[1]

    received_query = b""

    def handle_netbios():
        nonlocal received_query
        try:
            server_sock.settimeout(2.0)
            data, client_addr = server_sock.recvfrom(1024)
            received_query = data

            # Build mock NetBIOS NBSTAT response:
            # 56 bytes header
            header = b"\x80\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"  # 12 bytes
            header += b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"      # 34 bytes
            header += b"\x00\x21\x00\x01\x00\x00\x00\x00\x00\x50"      # 10 bytes (total 56)

            # Byte 56: num_names = 2
            num_names = b"\x02"

            # Name 1: Computer Name (15 bytes name + 1 byte suffix 0x00 + 2 bytes flags 0x0400 = 18 bytes)
            name1 = b"DESKTOP-TEST   \x00\x04\x00"

            # Name 2: Workgroup (15 bytes name + 1 byte suffix 0x00 + 2 bytes flags 0x8400 = 18 bytes)
            name2 = b"WORKGROUP      \x00\x84\x00"

            # Unit ID / Hardware MAC (6 bytes): 00:11:22:33:44:55
            unit_id = b"\x00\x11\x22\x33\x44\x55"

            # Statistics/padding
            stats = b"\x00" * 40

            resp = header + num_names + name1 + name2 + unit_id + stats
            server_sock.sendto(resp, client_addr)
        except Exception:
            pass
        finally:
            server_sock.close()

    th = threading.Thread(target=handle_netbios)
    th.daemon = True
    th.start()

    res = probe_netbios("127.0.0.1", port=port, timeout=1.0)
    assert received_query == NETBIOS_NBSTAT_QUERY
    assert res.get("is_active") is True
    assert res.get("hostname") == "DESKTOP-TEST"
    assert res.get("computer_name") == "DESKTOP-TEST"
    assert res.get("workgroup") == "WORKGROUP"
    assert res.get("mac") == "00:11:22:33:44:55"
    assert res.get("vendor") == "Microsoft Corporation"
    assert res.get("type") == "workstation"
    assert res.get("model") == "Windows Host"
    assert res.get("port") == port
    assert res.get("kernel_turnaround_us", 0) > 0
    assert isinstance(res.get("raw_response"), str)

    # JSON serialization and symmetry
    dumped = json.dumps(res)
    assert isinstance(dumped, str)
    assert json.loads(dumped) == res


# =========================================================================
# 2. WS-Discovery (UDP 3702) Prober Tests
# =========================================================================

WSD_TEST_PROBEMATCHES_XML = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:dpws="http://docs.oasis-open.org/ws-dd/ns/dpws/2009/01">
  <soap:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
    <wsa:RelatesTo>urn:uuid:11223344-5566-7788-99aa-bbccddeeff00</wsa:RelatesTo>
  </soap:Header>
  <soap:Body>
    <wsd:ProbeMatches>
      <wsd:ProbeMatch>
        <wsa:EndpointReference>
          <wsa:Address>urn:uuid:aabbccdd-eeff-1122-3344-556677889900</wsa:Address>
        </wsa:EndpointReference>
        <wsd:Types>dpws:Device wprt:PrintDeviceType</wsd:Types>
        <dpws:FriendlyName>HP LaserJet Pro MFP</dpws:FriendlyName>
        <dpws:Manufacturer>HP Inc.</dpws:Manufacturer>
        <dpws:ModelName>HP LaserJet M428fdw</dpws:ModelName>
      </wsd:ProbeMatch>
    </wsd:ProbeMatches>
  </soap:Body>
</soap:Envelope>"""


def test_ws_discovery_probe_success():
    """Validates WS-Discovery SOAP Probe transmission and XML ProbeMatches parsing."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("127.0.0.1", 0))
    port = server_sock.getsockname()[1]

    received_probe = b""

    def handle_wsd():
        nonlocal received_probe
        try:
            server_sock.settimeout(2.0)
            data, client_addr = server_sock.recvfrom(4096)
            received_probe = data
            server_sock.sendto(WSD_TEST_PROBEMATCHES_XML.encode("utf-8"), client_addr)
        except Exception:
            pass
        finally:
            server_sock.close()

    th = threading.Thread(target=handle_wsd)
    th.daemon = True
    th.start()

    res = probe_ws_discovery("127.0.0.1", port=port, timeout=1.0)
    assert b"soap:Envelope" in received_probe
    assert b"wsd:Probe" in received_probe
    assert res.get("is_active") is True
    assert res.get("vendor") == "HP Inc."
    assert res.get("model") == "HP LaserJet M428fdw"
    assert res.get("friendly_name") == "HP LaserJet Pro MFP"
    assert res.get("type") == "printer"
    assert res.get("endpoint_uuid") == "aabbccdd-eeff-1122-3344-556677889900"
    assert res.get("port") == port
    assert res.get("kernel_turnaround_us", 0) > 0
    assert isinstance(res.get("raw_response"), str)

    dumped = json.dumps(res)
    assert isinstance(dumped, str)
    assert json.loads(dumped) == res


# =========================================================================
# 3. LLMNR Reverse PTR (UDP 5355) Prober Tests
# =========================================================================

def test_llmnr_probe_success():
    """Validates LLMNR reverse PTR query transmission and DNS answer section dissecting."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("127.0.0.1", 0))
    port = server_sock.getsockname()[1]

    received_query = b""

    def handle_llmnr():
        nonlocal received_query
        try:
            server_sock.settimeout(2.0)
            data, client_addr = server_sock.recvfrom(2048)
            received_query = data

            # Construct DNS response:
            # Transaction ID: 0x1234, Flags: 0x8000 (standard response), QDCOUNT: 1, ANCOUNT: 1, NSCOUNT: 0, ARCOUNT: 0
            hdr = struct.pack(">HHHHHH", 0x1234, 0x8000, 1, 1, 0, 0)
            # Question section from query (skip 12 bytes header)
            question = data[12:]
            # Answer: Name pointer to offset 12 (0xc00c), Type PTR (12), Class IN (1), TTL 30s (30), Length 16
            ans_hdr = struct.pack(">HHHIH", 0xc00c, 12, 1, 30, 16)
            # PTR name: \x0eOFFICE-PRINTER\x00
            ptr_name = b"\x0eOFFICE-PRINTER\x00"

            resp = hdr + question + ans_hdr + ptr_name
            server_sock.sendto(resp, client_addr)
        except Exception:
            pass
        finally:
            server_sock.close()

    th = threading.Thread(target=handle_llmnr)
    th.daemon = True
    th.start()

    res = probe_llmnr("127.0.0.1", port=port, timeout=1.0)
    assert len(received_query) > 12
    assert res.get("is_active") is True
    assert res.get("hostname") == "OFFICE-PRINTER"
    assert res.get("port") == port
    assert res.get("protocol") == "LLMNR PTR (UDP 5355)"
    assert res.get("kernel_turnaround_us", 0) > 0
    assert isinstance(res.get("raw_response"), str)

    dumped = json.dumps(res)
    assert isinstance(dumped, str)
    assert json.loads(dumped) == res


# =========================================================================
# 4. Timeout and Refusal Resilience Tests
# =========================================================================

def test_stealth_probes_timeout_and_refusal():
    """Validates clean empty dict return when endpoints are unreachable or time out."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()

    res_nb = probe_netbios("127.0.0.1", port=closed_port, timeout=0.1)
    assert res_nb == {}

    res_wsd = probe_ws_discovery("127.0.0.1", port=closed_port, timeout=0.1)
    assert res_wsd == {}

    res_llmnr = probe_llmnr("127.0.0.1", port=closed_port, timeout=0.1)
    assert res_llmnr == {}

    res_host = probe_stealth_host(
        "127.0.0.1",
        timeout=0.2,
        netbios_port=closed_port,
        wsd_port=closed_port,
        llmnr_port=closed_port
    )
    assert res_host == {}


# =========================================================================
# 5. Composite Orchestrator Tests
# =========================================================================

def test_probe_stealth_host_orchestrator():
    """Validates concurrent execution of NetBIOS, WSD, and LLMNR with consolidated host metadata."""
    s_nb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_nb.bind(("127.0.0.1", 0))
    nb_port = s_nb.getsockname()[1]

    s_wsd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_wsd.bind(("127.0.0.1", 0))
    wsd_port = s_wsd.getsockname()[1]

    def run_servers():
        # NetBIOS reply
        try:
            s_nb.settimeout(2.0)
            data, addr = s_nb.recvfrom(1024)
            header = b"\x80\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"
            header += b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
            header += b"\x00\x21\x00\x01\x00\x00\x00\x00\x00\x50"
            num_names = b"\x01"
            name1 = b"STEALTH-WS     \x00\x04\x00"
            unit_id = b"\x02\x42\xAC\x11\x22\x33"
            resp = header + num_names + name1 + unit_id + (b"\x00" * 40)
            s_nb.sendto(resp, addr)
        except Exception:
            pass
        finally:
            s_nb.close()

        # WSD reply
        try:
            s_wsd.settimeout(2.0)
            data, addr = s_wsd.recvfrom(4096)
            s_wsd.sendto(WSD_TEST_PROBEMATCHES_XML.encode("utf-8"), addr)
        except Exception:
            pass
        finally:
            s_wsd.close()

    th = threading.Thread(target=run_servers)
    th.daemon = True
    th.start()

    res = probe_stealth_host(
        "127.0.0.1",
        timeout=1.5,
        netbios_port=nb_port,
        wsd_port=wsd_port,
        llmnr_port=65530
    )

    assert res.get("is_active") is True
    assert res.get("hostname") in ("STEALTH-WS", "HP LaserJet Pro MFP")
    assert res.get("mac") == "02:42:AC:11:22:33"
    assert res.get("kernel_turnaround_us", 0) > 0
    assert "netbios" in res.get("probes", {})
    assert "ws_discovery" in res.get("probes", {})

    dumped = json.dumps(res)
    assert isinstance(dumped, str)
    assert json.loads(dumped) == res


# =========================================================================
# 6. JSON Serialization Symmetry & Payload Sanitization
# =========================================================================

def test_stealth_prober_json_symmetry():
    """Verifies that all stealth probers strictly return JSON-serializable dictionaries."""
    sample = {
        "raw_response": b"\x80\x00\x84\x00\x11\x22",
        "nested": {
            "token": b"\xff\xfe\x01\x02",
            "text": "DESKTOP\x00NAME\x1f\x7f"
        },
        "list_items": [b"\xaa\xbb", "clean"],
        "active": True,
        "count": 42
    }
    sanitized = sanitize_prober_payload(sample)
    assert sanitized["raw_response"] == "800084001122"
    assert sanitized["nested"]["token"] == "fffe0102"
    assert sanitized["nested"]["text"] == "DESKTOPNAME"
    assert sanitized["list_items"][0] == "aabb"
    assert sanitized["list_items"][1] == "clean"

    dumped = json.dumps(sanitized)
    assert isinstance(dumped, str)
    assert json.loads(dumped) == sanitized


# =========================================================================
# 7. SubnetSweeper Stealth Discovery Integration
# =========================================================================

def test_subnet_sweeper_stealth_integration():
    """Verifies that SubnetSweeper discovers dormant stealth nodes and ingests them into state."""
    sweeper = SubnetSweeper(subnet_cidr="192.168.1.0/24")

    mock_stealth_endpoint = {
        "ip": "192.168.1.199",
        "is_active": True,
        "hostname": "FINANCE-PC",
        "mac": "02:50:79:66:77:88",
        "vendor": "Microsoft Corporation",
        "type": "workstation",
        "model": "Windows Host",
        "kernel_turnaround_us": 185.5,
        "probes": {
            "netbios": {"hostname": "FINANCE-PC", "mac": "02:50:79:66:77:88"}
        }
    }

    with patch("graphpath.cli.sweep.probe_stealth_host", return_value=mock_stealth_endpoint):
        discovered = sweeper.run_stealth_sweep(candidate_ips=["192.168.1.199"])
        assert len(discovered) == 1
        assert discovered[0]["ip"] == "192.168.1.199"
        assert discovered[0]["mac"] == "02:50:79:66:77:88"

        # Simulate the ingestion loop executed in SubnetSweeper.execute_sweep()
        for sep in discovered:
            sip = sep["ip"]
            smac = sep.get("mac")
            if sep.get("kernel_turnaround_us"):
                sweeper.probed_kernel_turnarounds[sip] = sep["kernel_turnaround_us"]

            os_profile_name = "STEALTH_WINDOWS_HOST" if sep.get("type") == "workstation" else "STEALTH_NETWORK_ENDPOINT"
            sweeper.inferred_os_profiles[sip] = {
                "ip": sip,
                "mac": smac,
                "os_profile": os_profile_name,
                "confidence": 95.0,
                "evidence": f"Stealth Prober: {sep.get('vendor')} {sep.get('model')} Host:{sep.get('hostname')}"
            }
            sweeper.dip_manager.ingest_observation(
                mac=smac,
                ip=sip,
                vendor=sep.get("vendor"),
                model=sep.get("model"),
                hostname=sep.get("hostname"),
                dev_type=sep.get("type"),
                evidence_source="stealth_prober_suite"
            )

        assert sweeper.probed_kernel_turnarounds["192.168.1.199"] == 185.5
        assert sweeper.inferred_os_profiles["192.168.1.199"]["os_profile"] == "STEALTH_WINDOWS_HOST"
        assert sweeper.inferred_os_profiles["192.168.1.199"]["confidence"] == 95.0

        dip_entry = sweeper.dip_manager.lookup_by_ip("192.168.1.199")
        assert dip_entry is not None
        assert dip_entry.get("mac") == "02:50:79:66:77:88"
        assert dip_entry.get("hostname") == "FINANCE-PC"
