"""
Project AETHERIS - Unit Tests for CLDAP Active Directory Discovery Engine (UDP 389)
Verifies:
  - ASN.1 BER searchRequest ping generation (RFC 1798 / MS-ADTS 6.3.5)
  - Authoritative MS-ADTS 6.3.5 NETLOGON_SAM_LOGON_RESPONSE_EX binary dissection
  - Capability flags decoding (PDC, GC, KDC, Writable) and UUID byte-order fidelity
  - Graceful fallback parsing on legacy/truncated Netlogon frames
  - Bounded UDP loopback communication and microsecond turnaround telemetry
  - Sub-0.4s timeout enforcement on unresponsive targets
  - Zero raw bytes and JSON round-trip invariance
  - Package exports and module integration
"""

import json
import select
import socket
import struct
import threading
import time
import uuid
from typing import Optional, Dict, Any

import pytest

from aetheris.core.probers import (
    probe_cldap_endpoint,
    build_cldap_netlogon_ping,
    parse_cldap_response,
)
from aetheris.core.probers.cldap import (
    _ber_tag,
    DS_PDC_FLAG,
    DS_GC_FLAG,
    DS_KDC_FLAG,
    DS_WRITABLE_FLAG,
    NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE_EX,
    NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE,
)


def build_mock_netlogon_response(
    opcode: int = NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE_EX,
    sbz: int = 0,
    flags: int = 0x00003FD3,  # PDC | GC | LDAP | DS | KDC | TIMESERV | CLOSEST | WRITABLE | GOOD_TIMESERV
    guid: Optional[uuid.UUID] = None,
    forest: str = "corp.aetheris.local",
    domain: str = "corp.aetheris.local",
    dc_hostname: str = "dc01.corp.aetheris.local",
    netbios_domain: str = "AETHERIS",
    netbios_computer: str = "DC01",
    user_name: str = "",
    dc_site: str = "Default-First-Site-Name",
    client_site: str = "Default-First-Site-Name",
    wrap_in_cldap_asn1: bool = True,
) -> bytes:
    """Constructs a binary Netlogon response matching MS-ADTS 6.3.5 specifications."""
    if guid is None:
        guid = uuid.UUID("12345678-1234-5678-1234-567812345678")

    header = struct.pack("<HHI", opcode, sbz, flags)
    guid_bytes = guid.bytes_le if opcode == NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE_EX else b""
    payload = (
        header
        + guid_bytes
        + forest.encode("utf-8")
        + b"\x00"
        + domain.encode("utf-8")
        + b"\x00"
        + dc_hostname.encode("utf-8")
        + b"\x00"
        + netbios_domain.encode("utf-8")
        + b"\x00"
        + netbios_computer.encode("utf-8")
        + b"\x00"
        + user_name.encode("utf-8")
        + b"\x00"
        + dc_site.encode("utf-8")
        + b"\x00"
        + client_site.encode("utf-8")
        + b"\x00"
    )

    if not wrap_in_cldap_asn1:
        return payload

    # Wrap in ASN.1 BER LDAP Message
    val_tag = _ber_tag(0x04, payload)
    vals_set = _ber_tag(0x31, val_tag)
    attr_type = _ber_tag(0x04, b"netlogon")
    attr_seq = _ber_tag(0x30, attr_type + vals_set)
    attr_list = _ber_tag(0x30, attr_seq)
    obj_name = _ber_tag(0x04, b"")
    search_entry = _ber_tag(0x64, obj_name + attr_list)
    msg_id = _ber_tag(0x02, b"\x01")
    return _ber_tag(0x30, msg_id + search_entry)


class TestCldapProber:
    """Test suite verifying CLDAP UDP 389 Active Directory Engine capabilities."""

    def test_package_exports(self):
        """Assert core CLDAP prober functions are exported in aetheris.core.probers."""
        import aetheris.core.probers as probers
        assert hasattr(probers, "probe_cldap_endpoint")
        assert hasattr(probers, "build_cldap_netlogon_ping")
        assert hasattr(probers, "parse_cldap_response")

    def test_build_cldap_netlogon_ping_structure(self):
        """Verify ASN.1 BER encoding of LDAP searchRequest ping."""
        # Ping without domain hint
        ping_generic = build_cldap_netlogon_ping()
        assert isinstance(ping_generic, bytes)
        assert len(ping_generic) > 30
        assert ping_generic[0] == 0x30  # SEQUENCE
        assert b"netlogon" in ping_generic
        assert b"NtVer" in ping_generic
        assert b"\x06\x00\x00\x20" in ping_generic

        # Ping with domain hint
        ping_domain = build_cldap_netlogon_ping("corp.aetheris.local")
        assert isinstance(ping_domain, bytes)
        assert b"corp.aetheris.local" in ping_domain
        assert b"DnsDomain" in ping_domain

    def test_parse_cldap_netlogon_response_ex_synthetic(self):
        """Verify parsing of MS-ADTS 6.3.5 NETLOGON_SAM_LOGON_RESPONSE_EX binary structure."""
        test_guid = uuid.UUID("abcdef01-2345-6789-abcd-ef0123456789")
        frame = build_mock_netlogon_response(
            opcode=NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE_EX,
            flags=DS_PDC_FLAG | DS_GC_FLAG | DS_KDC_FLAG | DS_WRITABLE_FLAG,
            guid=test_guid,
            forest="root.contoso.com",
            domain="sub.contoso.com",
            dc_hostname="dc02.sub.contoso.com",
            netbios_domain="SUBCONTOSO",
            netbios_computer="DC02",
            dc_site="NorthAmerica-East",
            client_site="Branch-Office-1",
            wrap_in_cldap_asn1=True,
        )

        res = parse_cldap_response(frame)
        assert res is not None
        assert res["is_ad_controller"] is True
        assert res["type"] == "server"
        assert res["role"] == "Active Directory Domain Controller"
        assert res["vendor"] == "Microsoft Corporation"
        assert res["forest"] == "root.contoso.com"
        assert res["domain"] == "sub.contoso.com"
        assert res["dc_hostname"] == "dc02.sub.contoso.com"
        assert res["netbios_domain"] == "SUBCONTOSO"
        assert res["netbios_computer_name"] == "DC02"
        assert res["dc_site"] == "NorthAmerica-East"
        assert res["client_site"] == "Branch-Office-1"
        assert res["domain_guid"] == str(test_guid)
        assert res["is_pdc"] is True
        assert res["is_gc"] is True
        assert res["is_kdc"] is True
        assert res["is_writable"] is True
        assert res["parsing_mode"] == "ms_adts_6_3_5_response_ex"

    def test_parse_unwrapped_netlogon_buffer(self):
        """Verify parsing when raw buffer contains unwrapped Netlogon frame."""
        raw_frame = build_mock_netlogon_response(
            forest="standalone.local",
            domain="standalone.local",
            dc_hostname="dc99.standalone.local",
            wrap_in_cldap_asn1=False,
        )
        res = parse_cldap_response(raw_frame)
        assert res is not None
        assert res["is_ad_controller"] is True
        assert res["domain"] == "standalone.local"
        assert res["dc_hostname"] == "dc99.standalone.local"

    def test_parse_cldap_legacy_response(self):
        """Verify handling of legacy non-extended Opcode 18 Netlogon framing."""
        legacy_frame = build_mock_netlogon_response(
            opcode=NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE,
            forest="legacy.contoso.local",
            domain="legacy.contoso.local",
            dc_hostname="legacydc.contoso.local",
            wrap_in_cldap_asn1=True,
        )
        res = parse_cldap_response(legacy_frame)
        assert res is not None
        assert res["is_ad_controller"] is True
        assert res["parsing_mode"] == "ms_adts_legacy_response"
        assert res["domain"] == "legacy.contoso.local"

    def test_parse_corrupted_or_empty_response(self):
        """Assert graceful handling of invalid, empty, or truncated frames."""
        assert parse_cldap_response(b"") is None
        assert parse_cldap_response(b"\x00" * 10) is None
        assert parse_cldap_response(b"Random unstructured junk data that is not LDAP") is None

    def test_fallback_token_scan_on_partial_match(self):
        """Verify heuristic recovery when 'netlogon' keyword exists but structure is damaged."""
        damaged_frame = b"\x30\x40netlogon\x04\x10junk\x00corp.domain.local\x00MYDC01\x00"
        res = parse_cldap_response(damaged_frame)
        assert res is not None
        assert res["is_ad_controller"] is True
        assert res["domain"] == "corp.domain.local"

    def test_probe_cldap_endpoint_mock_server(self):
        """Test UDP probe round-trip against a local ephemeral loopback responder."""
        # Ephemeral UDP server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind(("127.0.0.1", 0))
        server_port = server_sock.getsockname()[1]
        stop_event = threading.Event()

        mock_guid = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
        response_bytes = build_mock_netlogon_response(
            guid=mock_guid,
            forest="lab.aetheris.internal",
            domain="lab.aetheris.internal",
            dc_hostname="lab-dc1.aetheris.internal",
            netbios_domain="LAB",
            netbios_computer="LAB-DC1",
            dc_site="Lab-Site",
            client_site="Lab-Site",
        )

        def responder():
            try:
                server_sock.settimeout(1.0)
                while not stop_event.is_set():
                    try:
                        data, addr = server_sock.recvfrom(2048)
                        # Verify we received an LDAP ping
                        if b"netlogon" in data:
                            server_sock.sendto(response_bytes, addr)
                            break
                    except socket.timeout:
                        continue
            finally:
                server_sock.close()

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()

        try:
            res = probe_cldap_endpoint("127.0.0.1", port=server_port, timeout=0.4)
            assert res["is_ad_controller"] is True
            assert res["domain"] == "lab.aetheris.internal"
            assert res["dc_hostname"] == "lab-dc1.aetheris.internal"
            assert res["domain_guid"] == str(mock_guid)
            assert "kernel_turnaround_us" in res
            assert res["kernel_turnaround_us"] > 0
            assert "rtt_ms" in res
            assert res["target_port"] == server_port
        finally:
            stop_event.set()
            thread.join(timeout=1.0)

    def test_probe_cldap_endpoint_timeout_enforcement(self):
        """Assert strict timeout enforcement (<= 0.4s) when probing unreachable host."""
        # Use unrouteable documentation IP / closed UDP port
        t0 = time.perf_counter()
        res = probe_cldap_endpoint("192.0.2.1", port=389, timeout=0.2)
        elapsed = time.perf_counter() - t0

        assert elapsed < 0.45  # Enforce sub-0.45s ceiling
        assert res["is_ad_controller"] is False
        assert res["error"] == "timeout"
        assert res["target_ip"] == "192.0.2.1"

    def test_cldap_payload_sanitization_and_json_symmetry(self):
        """Assert strict compliance with zero raw bytes and JSON round-trip invariance."""
        frame = build_mock_netlogon_response(
            forest="corp.clean.org",
            domain="corp.clean.org",
            dc_hostname="dc01.corp.clean.org",
        )
        res = parse_cldap_response(frame)
        assert res is not None

        # Check JSON round-trip invariance
        serialized = json.dumps(res)
        deserialized = json.loads(serialized)
        assert deserialized == res

        # Ensure no byte objects exist anywhere in output dictionary
        for k, v in res.items():
            assert not isinstance(v, bytes), f"Key {k} contains un-sanitized raw bytes: {v}"
