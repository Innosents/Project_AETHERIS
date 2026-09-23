"""
Unit test suite for DeepProberPort and deep_prober adapters.
Validates AST boundary isolation, protocol conformance, pure ONVIF/HTTP response parsing,
coordinator routing across all protocol vectors, mapping compatibility, and safe fallback handling.
"""
import ast
import os
import pytest
from unittest.mock import patch

from aetheris.core.ports.deep_prober_port import (
    DeepProberPort,
    DeepProbeEndpointResult,
    OnvifDeviceInfo,
    TlsCertInfo,
    _MappingCompatibleModel,
)
from aetheris.discovery.deep_prober import (
    DeepProber,
    SmbProber,
    WinRmProber,
    RpcProber,
    RdpProber,
    SipProber,
    WebDeepProber,
    RtspProber,
    SsdpProber,
    ModbusProber,
    MercuryMspProber,
    SshProber,
    HttpTitleProber,
)


def test_deep_prober_port_ast_boundary():
    """Verify deep_prober_port.py contains zero socket, ssl, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "deep_prober_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"socket", "ssl", "scapy", "subprocess", "sqlite3", "redis", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_deep_prober_protocol_conformance():
    """Verify DeepProber coordinator satisfies DeepProberPort protocol."""
    prober = DeepProber()
    assert isinstance(prober, DeepProberPort)


def test_onvif_soap_pure_parsing():
    """Verify in-memory parsing of ONVIF GetDeviceInformation SOAP response."""
    soap_resp = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        '<soap:Body>'
        '<tds:GetDeviceInformationResponse>'
        '<tds:Manufacturer>Axis Communications</tds:Manufacturer>'
        '<tds:Model>AXIS M3045-V</tds:Model>'
        '<tds:FirmwareVersion>9.80.3</tds:FirmwareVersion>'
        '</tds:GetDeviceInformationResponse>'
        '</soap:Body>'
        '</soap:Envelope>'
    )
    info = DeepProber.parse_onvif_soap_response(soap_resp)
    assert info is not None
    assert info.vendor == "Axis Communications"
    assert info.model == "AXIS M3045-V"
    assert info.firmware == "9.80.3"
    assert info["type"] == "camera"
    assert info.get("vendor") == "Axis Communications"
    assert "vendor" in info


def test_onvif_soap_pure_parsing_empty_or_invalid():
    """Verify ONVIF SOAP parser handles empty or non-matching payload gracefully."""
    assert DeepProber.parse_onvif_soap_response("") is None
    assert DeepProber.parse_onvif_soap_response("<html>Not SOAP</html>") is None


def test_http_identity_pure_parsing():
    """Verify pure parsing of HTTP Server header and title."""
    http_data = (
        "HTTP/1.1 200 OK\r\n"
        "Server: lighttpd/1.4.55\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><head><title>Edge Gateway Configuration</title></head></html>"
    )
    res = DeepProber.parse_http_identity(http_data)
    assert res["server"] == "lighttpd/1.4.55"
    assert res["title"] == "Edge Gateway Configuration"


def test_http_identity_pure_parsing_empty():
    """Verify pure parsing on empty response."""
    res = DeepProber.parse_http_identity("")
    assert res["server"] == ""
    assert res["title"] == ""


def test_mapping_compatible_models():
    """Verify dict-like indexing, .get, containment, and immutability for all port models."""
    res = DeepProbeEndpointResult(
        ip="192.168.1.50",
        port=445,
        protocol="SMB",
        vendor="Microsoft",
        model=None,
        os_version="Windows 11",
        type="workstation",
        banner="SMB Banner",
        details={"domain": "WORKGROUP"},
    )
    assert res["ip"] == "192.168.1.50"
    assert res.get("protocol") == "SMB"
    assert res.get("nonexistent", "fallback") == "fallback"
    assert "port" in res
    with pytest.raises(Exception):
        res.port = 80  # frozen model

    tls = TlsCertInfo(port=443, common_name="gw.local", organization="Acme Corp")
    assert tls["common_name"] == "gw.local"
    assert tls.get("organization") == "Acme Corp"
    assert "common_name" in tls


def test_deep_prober_coordinator_routing():
    """Verify DeepProber routes each target port to the expected discrete prober."""
    prober = DeepProber()

    # SMB 445
    with patch.object(SmbProber, "probe_smb", return_value={"port": 445, "protocol": "SMB", "os_version": "Windows Host", "domain": "WORKGROUP"}):
        result = prober.probe_port("192.168.1.10", 445)
        assert result is not None
        assert result.protocol == "SMB"
        assert result.os_version == "Windows Host"
        assert result.details.get("domain") == "WORKGROUP"

    # WinRM 5985
    with patch.object(WinRmProber, "probe_winrm", return_value={"port": 5985, "protocol": "WinRM", "vendor": "Microsoft Corporation", "os_version": "Windows 11", "type": "workstation"}):
        result = prober.probe_port("192.168.1.11", 5985)
        assert result is not None
        assert result.protocol == "WinRM"
        assert result.vendor == "Microsoft Corporation"

    # RPC 135
    with patch.object(RpcProber, "probe_rpc", return_value={"port": 135, "protocol": "DCE/RPC", "vendor": "Microsoft Corporation", "interfaces": []}):
        result = prober.probe_port("192.168.1.12", 135)
        assert result is not None
        assert result.protocol == "DCE/RPC"

    # RDP 3389
    with patch.object(RdpProber, "probe_rdp", return_value={"port": 3389, "protocol": "RDP", "vendor": "Microsoft Corporation", "type": "workstation"}):
        result = prober.probe_port("192.168.1.13", 3389)
        assert result is not None
        assert result.protocol == "RDP"

    # SIP 5060
    with patch.object(SipProber, "probe_sip", return_value={"port": 5060, "protocol": "SIP", "type": "voip_phone", "sip_user_agent": "Polycom-VVX"}):
        result = prober.probe_port("192.168.1.14", 5060)
        assert result is not None
        assert result.protocol == "SIP"
        assert result.banner == "Polycom-VVX"

    # Web / ONVIF / TLS (Port 80 / 443)
    with patch.object(WebDeepProber, "probe_onvif_soap", return_value={"vendor": "Axis Communications", "model": "M3045", "firmware": "9.80", "type": "camera"}), \
         patch.object(HttpTitleProber, "probe_web_identity", return_value={"port": 80, "server": "Apache", "title": "Axis Camera", "protocol": "HTTP"}):
        result = prober.probe_port("192.168.1.15", 80)
        assert result is not None
        assert result.vendor == "Axis Communications"
        assert result.model == "M3045"
        assert result.type == "camera"
        assert "Server: Apache" in (result.banner or "")

    # RTSP 554
    with patch.object(RtspProber, "probe_rtsp", return_value={"port": 554, "protocol": "RTSP", "type": "camera", "rtsp_server": "Hikvision RTSP Server"}):
        result = prober.probe_port("192.168.1.16", 554)
        assert result is not None
        assert result.protocol == "RTSP"
        assert result.banner == "Hikvision RTSP Server"

    # Modbus 502
    with patch.object(ModbusProber, "probe_modbus", return_value={"port": 502, "protocol": "MODBUS", "type": "plc", "vendor": "Schneider", "model": "M241"}):
        result = prober.probe_port("192.168.1.17", 502)
        assert result is not None
        assert result.protocol == "MODBUS"
        assert result.vendor == "Schneider"

    # Mercury MSP 3001
    with patch.object(MercuryMspProber, "probe_msp", return_value={"port": 3001, "protocol": "MSP", "type": "access_control", "model": "Mercury LP1502"}):
        result = prober.probe_port("192.168.1.18", 3001)
        assert result is not None
        assert result.protocol == "MSP"
        assert result.model == "Mercury LP1502"

    # SSH 22
    with patch.object(SshProber, "probe_ssh_banner", return_value={"protocol": "SSH", "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu", "os_hint": "Ubuntu Linux", "type": "server"}):
        result = prober.probe_port("192.168.1.19", 22)
        assert result is not None
        assert result.protocol == "SSH"
        assert result.banner == "SSH-2.0-OpenSSH_8.9p1 Ubuntu"
        assert result.os_version == "Ubuntu Linux"

    # SSDP 1900
    with patch.object(SsdpProber, "probe_ssdp", return_value={"protocol": "SSDP", "port": 1900}):
        result = prober.probe_port("192.168.1.20", 1900)
        assert result is not None
        assert result.protocol == "SSDP"

    # Unknown port
    assert prober.probe_port("192.168.1.21", 65534) is None


def test_discrete_probers_safe_unreachable_call():
    """Verify individual probers return empty dict or None when connecting to unreachable port."""
    assert SmbProber.probe_smb("127.0.0.1", 65534, timeout=0.01) == {}
    assert SshProber.probe_ssh_banner("127.0.0.1", 65534, timeout=0.01) == {}
    assert RtspProber.probe_rtsp("127.0.0.1", 65534, timeout=0.01) == {}
    assert WinRmProber.probe_winrm("127.0.0.1", 65534, timeout=0.01) == {}
    assert RpcProber.probe_rpc("127.0.0.1", 65534, timeout=0.01) == {}
    assert RdpProber.probe_rdp("127.0.0.1", 65534, timeout=0.01) == {}
    assert ModbusProber.probe_modbus("127.0.0.1", 65534, timeout=0.01) == {}
    assert MercuryMspProber.probe_msp("127.0.0.1", 65534, timeout=0.01) == {}
