"""
Unit Tests for Mercury Security (Port 3001) and ONVIF (Port 80/8000) Reactive Probers
Validates binary status inquiry frame transmission, kernel turnaround calculation,
SOAP GetDeviceInformation parsing, timeout resilience, Bayesian fusion, and SQLite persistence.
"""

import socket
import threading
import time
import tempfile
import sqlite3
import json
import pytest
from http.server import HTTPServer, BaseHTTPRequestHandler

from graphpath.core.probers.mercury_probe import probe_mercury_panel, MERCURY_STATUS_INQUIRY
from graphpath.core.probers.onvif_probe import probe_onvif_camera
from graphpath.core.probers.bacnet_probe import probe_bacnet_device, BACNET_READ_PROPERTY_INQUIRY
from graphpath.core.probers.modbus_probe import probe_modbus_device, MODBUS_READ_DEVICE_ID
from graphpath.core.probers.sanitization import sanitize_prober_payload, clean_ascii_string
from graphpath.core.spatial_bayesian import BayesianEvidenceFusion
from graphpath.discovery.fingerprint import PassiveStackClassifier


# =========================================================================
# 1. Mercury Security (Port 3001) Prober Tests
# =========================================================================

def test_mercury_probe_success():
    """Validates Mercury panel probing with text model and firmware signature."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    received_payload = b""

    def handle_client():
        nonlocal received_payload
        try:
            client, _ = server_sock.accept()
            received_payload = client.recv(1024)
            # Send simulated Mercury status frame with model and firmware
            client.sendall(b"\x00\x10\x00\x02\x00\x00\x01\x18\x00\x00Mercury LP1502 Controller FW: 1.24")
            client.close()
        except Exception:
            pass
        finally:
            server_sock.close()

    th = threading.Thread(target=handle_client)
    th.daemon = True
    th.start()

    res = probe_mercury_panel("127.0.0.1", port=port, timeout=1.0)
    assert received_payload == MERCURY_STATUS_INQUIRY
    assert res.get("is_security_controller") is True
    assert res.get("vendor") == "Mercury Security"
    assert "LP1502" in res.get("model", "")
    assert res.get("firmware") == "1.24"
    assert res.get("archetype") == "INDUSTRIAL_OT"
    assert res.get("type") == "access_control"
    assert res.get("kernel_turnaround_us", 0) > 0
    assert isinstance(res.get("raw_response"), str)
    assert res["raw_response"] == b"\x00\x10\x00\x02\x00\x00\x01\x18\x00\x00Mercury LP1502 Controller FW: 1.24".hex()
    serialized = json.dumps(res)
    assert isinstance(serialized, str)
    assert json.loads(serialized) == res


def test_mercury_probe_binary_code_fallback():
    """Validates binary model code mapping (e.g. 0x08 -> LP4502) and byte-encoded firmware."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    def handle_client():
        try:
            client, _ = server_sock.accept()
            _ = client.recv(1024)
            # Binary frame: model_code 0x08 at byte 3, major 2, minor 5 at bytes 6, 7
            resp = bytes([0x00, 0x10, 0x00, 0x08, 0x00, 0x00, 0x02, 0x05, 0x00, 0x00])
            client.sendall(resp)
            client.close()
        except Exception:
            pass
        finally:
            server_sock.close()

    th = threading.Thread(target=handle_client)
    th.daemon = True
    th.start()

    res = probe_mercury_panel("127.0.0.1", port=port, timeout=1.0)
    assert res.get("is_security_controller") is True
    assert res.get("model") == "Mercury LP4502 High-Density Controller"
    assert res.get("firmware") == "2.5"
    assert res.get("kernel_turnaround_us", 0) > 0
    assert isinstance(res.get("raw_response"), str)
    assert res["raw_response"] == bytes([0x00, 0x10, 0x00, 0x08, 0x00, 0x00, 0x02, 0x05, 0x00, 0x00]).hex()
    serialized = json.dumps(res)
    assert isinstance(serialized, str)
    assert json.loads(serialized) == res


def test_mercury_probe_timeout_and_refusal():
    """Validates clean empty dict return when panel is offline or unreachable."""
    # Find an unused closed port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()

    res = probe_mercury_panel("127.0.0.1", port=closed_port, timeout=0.2)
    assert res == {}


# =========================================================================
# 2. ONVIF Camera (Port 80/8000) Prober Tests
# =========================================================================

ONVIF_TEST_RESPONSE_XML = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>Axis Communications</tds:Manufacturer>
      <tds:Model>AXIS P3245-V</tds:Model>
      <tds:FirmwareVersion>10.12.185</tds:FirmwareVersion>
      <tds:SerialNumber>ACCC8E123456</tds:SerialNumber>
      <tds:HardwareId>654</tds:HardwareId>
    </tds:GetDeviceInformationResponse>
  </soap:Body>
</soap:Envelope>"""


class MockOnvifHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/onvif/device_service":
            content_length = int(self.headers.get("Content-Length", 0))
            _ = self.rfile.read(content_length)
            resp_body = ONVIF_TEST_RESPONSE_XML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/soap+xml; charset=utf-8")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress console logging during unit tests


def test_onvif_probe_success():
    """Validates ONVIF SOAP GetDeviceInformation inquiry and XML response parsing."""
    server = HTTPServer(("127.0.0.1", 0), MockOnvifHandler)
    port = server.server_port

    th = threading.Thread(target=server.serve_forever)
    th.daemon = True
    th.start()

    try:
        res = probe_onvif_camera("127.0.0.1", port=port, timeout=1.5)
        assert res.get("is_onvif") is True
        assert res.get("vendor") == "Axis Communications"
        assert res.get("model") == "AXIS P3245-V"
        assert res.get("firmware") == "10.12.185"
        assert res.get("serial_number") == "ACCC8E123456"
        assert res.get("hardware_id") == "654"
        assert res.get("archetype") == "CCTV_VIDEO"
        assert res.get("type") == "camera"
        assert res.get("kernel_turnaround_us", 0) > 0
        assert res.get("latency_ms", 0) > 0
        serialized = json.dumps(res)
        assert isinstance(serialized, str)
        assert json.loads(serialized) == res
    finally:
        server.shutdown()
        server.server_close()


class MockNonOnvifHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        resp_body = b"<html><body>Not Found</body></html>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, format, *args):
        pass


def test_onvif_probe_non_onvif():
    """Validates safe empty dict return for non-ONVIF web endpoints."""
    server = HTTPServer(("127.0.0.1", 0), MockNonOnvifHandler)
    port = server.server_port

    th = threading.Thread(target=server.serve_forever)
    th.daemon = True
    th.start()

    try:
        res = probe_onvif_camera("127.0.0.1", port=port, timeout=1.0)
        assert res == {}
    finally:
        server.shutdown()
        server.server_close()


def test_onvif_probe_timeout():
    """Validates graceful empty dict return on connection refusal/timeout."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()

    res = probe_onvif_camera("127.0.0.1", port=closed_port, timeout=0.2)
    assert res == {}


# =========================================================================
# 3. BACnet/IP (Port 47808) Prober Tests
# =========================================================================

def test_bacnet_probe_success():
    """Validates BACnet/IP BVLL ReadProperty inquiry and response parsing."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("127.0.0.1", 0))
    port = server_sock.getsockname()[1]

    received_data = b""

    def handle_bacnet():
        nonlocal received_data
        try:
            server_sock.settimeout(2.0)
            received_data, client_addr = server_sock.recvfrom(1024)
            # BVLL header (0x81, 0x0a) + NPDU + APDU ComplexACK with Device Object Tag 0xC4
            # Tag 0xC4 followed by 4-byte instance: 0x00, 0x01, 0xe2, 0x40 (instance 123456)
            resp = b"\x81\x0a\x00\x10\x01\x20\x00\x30\x0c\xc4\x00\x01\xe2\x40\x19\x4d"
            server_sock.sendto(resp, client_addr)
        except Exception:
            pass
        finally:
            server_sock.close()

    th = threading.Thread(target=handle_bacnet)
    th.daemon = True
    th.start()

    res = probe_bacnet_device("127.0.0.1", port=port, timeout=1.0)
    assert received_data == BACNET_READ_PROPERTY_INQUIRY
    assert res.get("is_bacnet_device") is True
    assert res.get("archetype") == "INDUSTRIAL_OT"
    assert res.get("type") == "bacnet_controller"
    assert res.get("device_instance") == 123456
    assert "Instance 123456" in res.get("model", "")
    assert res.get("kernel_turnaround_us", 0) > 0
    assert isinstance(res.get("raw_response"), str)
    assert res["raw_response"] == b"\x81\x0a\x00\x10\x01\x20\x00\x30\x0c\xc4\x00\x01\xe2\x40\x19\x4d".hex()
    serialized = json.dumps(res)
    assert isinstance(serialized, str)
    assert json.loads(serialized) == res


def test_bacnet_probe_timeout():
    """Validates safe empty dict return on BACnet UDP timeout."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    res = probe_bacnet_device("127.0.0.1", port=port, timeout=0.2)
    assert res == {}


# =========================================================================
# 4. Modbus TCP (Port 502) Prober Tests
# =========================================================================

def test_modbus_probe_success():
    """Validates Modbus TCP MEI Read Device ID inquiry and ASCII field extraction."""
    # MBAP Header: TransID=0x0001, ProtoID=0x0000, Length=0x002B, UnitID=0x01
    mbap = b"\x00\x01\x00\x00\x00\x2b\x01"
    # MEI Header: FC=0x2B, MEIType=0x0E, ReadDevID=0x01, Conformity=0x01, More=0x00, Next=0x00, NumObjects=3
    mei_hdr = b"\x2b\x0e\x01\x01\x00\x00\x03"
    obj0 = b"\x00\x12Schneider Electric"
    obj1 = b"\x01\x09Modicon M"
    obj2 = b"\x02\x05v2.10"
    expected_resp = mbap + mei_hdr + obj0 + obj1 + obj2

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    received_payload = b""

    def handle_client():
        nonlocal received_payload
        try:
            client, _ = server_sock.accept()
            received_payload = client.recv(1024)
            client.sendall(expected_resp)
            client.close()
        except Exception:
            pass
        finally:
            server_sock.close()

    th = threading.Thread(target=handle_client)
    th.daemon = True
    th.start()

    res = probe_modbus_device("127.0.0.1", port=port, timeout=1.0)
    assert received_payload == MODBUS_READ_DEVICE_ID
    assert res.get("is_modbus_device") is True
    assert res.get("archetype") == "INDUSTRIAL_OT"
    assert res.get("type") == "modbus_plc"
    assert res.get("vendor") == "Schneider Electric"
    assert res.get("model") == "Modicon M"
    assert res.get("firmware") == "v2.10"
    assert res.get("kernel_turnaround_us", 0) > 0
    assert isinstance(res.get("raw_response"), str)
    assert res["raw_response"] == expected_resp.hex()
    serialized = json.dumps(res)
    assert isinstance(serialized, str)
    assert json.loads(serialized) == res


def test_modbus_probe_refusal():
    """Validates safe empty dict return on closed port / connection refusal."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()

    res = probe_modbus_device("127.0.0.1", port=closed_port, timeout=0.2)
    assert res == {}


# =========================================================================
# 5. Bayesian Evidence Fusion Integration Tests
# =========================================================================

def test_bayesian_evidence_mercury_and_onvif():
    """Validates posterior probability convergence for Mercury and ONVIF evidence."""
    # 1. Mercury port 3001 evidence should converge to INDUSTRIAL_OT
    posteriors_mercury = BayesianEvidenceFusion.fuse_evidence(["port_mercury_3001"])
    assert posteriors_mercury["INDUSTRIAL_OT"] > 0.85
    assert posteriors_mercury["CCTV_VIDEO"] < 0.05

    # 2. ONVIF service evidence should converge to CCTV_VIDEO
    posteriors_onvif = BayesianEvidenceFusion.fuse_evidence(["port_onvif_80"])
    assert posteriors_onvif["CCTV_VIDEO"] > 0.85
    assert posteriors_onvif["INDUSTRIAL_OT"] < 0.10


def test_bayesian_evidence_bacnet_and_modbus():
    """Validates posterior probability convergence for BACnet and Modbus evidence."""
    # BACnet evidence convergence to INDUSTRIAL_OT >= 90%
    posteriors_bacnet = BayesianEvidenceFusion.fuse_evidence(["port_bacnet_47808", "bacnet_protocol_47808"])
    assert posteriors_bacnet["INDUSTRIAL_OT"] >= 0.90
    assert posteriors_bacnet["CCTV_VIDEO"] < 0.05

    # Modbus evidence convergence to INDUSTRIAL_OT >= 90%
    posteriors_modbus = BayesianEvidenceFusion.fuse_evidence(["port_modbus_502", "modbus_protocol_502"])
    assert posteriors_modbus["INDUSTRIAL_OT"] >= 0.90
    assert posteriors_modbus["CCTV_VIDEO"] < 0.05


# =========================================================================
# 6. Inferred OS Profiles Persistence Tests
# =========================================================================

def test_inferred_os_profiles_persistence():
    """Verifies that Mercury, ONVIF, BACnet, and Modbus profiles persist cleanly to SQLite inferred_os_profiles."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    classifier = PassiveStackClassifier(db_path=db_path)

    profiles = {
        "192.168.1.110": {
            "mac": "00:0F:9F:11:22:33",
            "os_profile": "MERCURY_ACCESS_CONTROLLER",
            "confidence": 99.0,
            "synack_ttl": 64,
            "window_size": 14600,
            "option55": "",
            "evidence": "Mercury MSP Probe (Port 3001): Mercury LP1502 Controller FW:1.24 t_kernel=280.0us"
        },
        "192.168.1.120": {
            "mac": "AC:CC:8E:11:22:33",
            "os_profile": "ONVIF_SURVEILLANCE_CAMERA",
            "confidence": 98.0,
            "synack_ttl": 64,
            "window_size": 29200,
            "option55": "",
            "evidence": "ONVIF SOAP Device Service (Port 80): Axis Communications AXIS P3245-V FW:10.12.185 t_kernel=1850.0us"
        },
        "192.168.1.130": {
            "mac": "00:10:E0:11:22:33",
            "os_profile": "BACNET_AUTOMATION_CONTROLLER",
            "confidence": 99.0,
            "synack_ttl": 64,
            "window_size": 14600,
            "option55": "",
            "evidence": "BACnet/IP BVLL ReadProperty (Port 47808): BACnet Controller (Instance 123456) t_kernel=280.0us"
        },
        "192.168.1.140": {
            "mac": "00:80:F4:11:22:33",
            "os_profile": "MODBUS_PLC_CONTROLLER",
            "confidence": 99.0,
            "synack_ttl": 64,
            "window_size": 14600,
            "option55": "",
            "evidence": "Modbus TCP MEI Read Device ID (Port 502): Schneider Electric Modicon M FW:v2.10 t_kernel=280.0us"
        }
    }

    classifier.save_to_ledger(profiles)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip, mac, os_profile, confidence, evidence FROM inferred_os_profiles ORDER BY ip")
        rows = cursor.fetchall()

    assert len(rows) == 4
    assert rows[0][0] == "192.168.1.110"
    assert rows[0][2] == "MERCURY_ACCESS_CONTROLLER"
    assert rows[0][3] == 99.0
    assert "LP1502" in rows[0][4]

    assert rows[1][0] == "192.168.1.120"
    assert rows[1][2] == "ONVIF_SURVEILLANCE_CAMERA"
    assert rows[1][3] == 98.0
    assert "AXIS P3245-V" in rows[1][4]

    assert rows[2][0] == "192.168.1.130"
    assert rows[2][2] == "BACNET_AUTOMATION_CONTROLLER"
    assert rows[2][3] == 99.0
    assert "BACnet Controller" in rows[2][4]

    assert rows[3][0] == "192.168.1.140"
    assert rows[3][2] == "MODBUS_PLC_CONTROLLER"
    assert rows[3][3] == 99.0
    assert "Schneider Electric" in rows[3][4]


# =========================================================================
# 7. JSON Serialization Hardening & Sanitization Unit Tests
# =========================================================================

def test_prober_payload_sanitization_helper():
    """Validates recursive sanitization, buffer bounding, and control character scrubbing."""
    sample = {
        "raw_bytes": b"\x81\x0a\x00\x0e",
        "nested_dict": {
            "sub_bytes": bytearray(b"\x00\x01\x02"),
            "dirty_text": "Schneider\x00Electric\x01\x1f\x7f",
        },
        "byte_list": [b"\xaa\xbb", "clean_string"],
        "large_buffer": b"\xff" * 2048,
        "integer_val": 42,
        "float_val": 3.1415,
        "bool_val": True,
        "none_val": None
    }
    sanitized = sanitize_prober_payload(sample, max_hex_bytes=1024)

    assert sanitized["raw_bytes"] == "810a000e"
    assert sanitized["nested_dict"]["sub_bytes"] == "000102"
    assert sanitized["nested_dict"]["dirty_text"] == "SchneiderElectric"
    assert sanitized["byte_list"][0] == "aabb"
    assert sanitized["byte_list"][1] == "clean_string"
    assert len(sanitized["large_buffer"]) == 2048  # 1024 bytes * 2 hex chars
    assert sanitized["integer_val"] == 42
    assert sanitized["float_val"] == 3.1415
    assert sanitized["bool_val"] is True
    assert sanitized["none_val"] is None

    # Full JSON serialization and symmetry check
    dumped = json.dumps(sanitized)
    assert isinstance(dumped, str)
    assert json.loads(dumped) == sanitized


def test_all_probers_json_serializability_and_symmetry():
    """Verifies that all probers return strictly JSON-serializable dictionaries on timeout/refusal."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()

    prober_funcs = [
        lambda: probe_mercury_panel("127.0.0.1", port=closed_port, timeout=0.1),
        lambda: probe_onvif_camera("127.0.0.1", port=closed_port, timeout=0.1),
        lambda: probe_bacnet_device("127.0.0.1", port=closed_port, timeout=0.1),
        lambda: probe_modbus_device("127.0.0.1", port=closed_port, timeout=0.1)
    ]

    for pfn in prober_funcs:
        res = pfn()
        assert isinstance(res, dict)
        dumped = json.dumps(res)
        assert isinstance(dumped, str)
        assert json.loads(dumped) == res


