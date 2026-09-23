"""
Unit test suite for DeviceFingerprintPort, fingerprint_device, and PassiveStackClassifier.
Validates AST boundary isolation, protocol conformance, pure rule heuristics, and schema immutability.
"""
import ast
import os
import pytest
from aetheris.core.ports.fingerprint_port import (
    DeviceFingerprintPort,
    DeviceFingerprintRecord,
    InferredOsProfileRecord,
)
from aetheris.discovery.fingerprint import fingerprint_device, PassiveStackClassifier


def test_fingerprint_port_ast_boundary():
    """Verify fingerprint_port.py contains zero sqlite3, socket, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "fingerprint_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"sqlite3", "socket", "scapy", "redis", "subprocess", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_fingerprint_axis_camera_heuristic():
    """Verify classification of an Axis network camera via RTSP port and banner."""
    res = fingerprint_device(
        ip="192.168.1.150",
        mac="00:40:8C:11:22:33",
        open_ports=[80, 554],
        banners={"554": "Server: AXIS M3046-V RTSP Server", "80": "Apache"},
        services=["rtsp", "http"]
    )
    assert isinstance(res, (DeviceFingerprintRecord, dict))
    assert res["type"] == "camera"
    assert res["vendor"] == "Axis Communications"
    assert "M3046-V" in res["model"]
    assert res.ip == res["ip"]


def test_fingerprint_mercury_controller_heuristic():
    """Verify classification of a Mercury access controller."""
    res = fingerprint_device(
        ip="192.168.1.200",
        mac="00:0F:E5:AA:BB:CC",
        open_ports=[3001],
        banners={"3001": "MERCURY_LP1502_READY"},
        services=["msp"]
    )
    assert res["type"] == "access_control"
    assert res["vendor"] == "Mercury Security"
    assert "MP1502" in res["model"] or "LP1502" in res["model"] or "Mercury" in res["model"]


def test_passive_stack_classifier_pure_inference():
    """Verify pure in-memory OS stack profile determination."""
    # Windows NT signature
    win_profile = PassiveStackClassifier.infer_os_profile(
        ttl=128,
        window_size=64240,
        option55="1,3,6,15,31,33,43,44,46,47,119,121,249,252"
    )
    assert win_profile["os_profile"] == "WINDOWS_NT"
    assert win_profile["confidence"] >= 95.0

    # Samsung Tizen OS signature
    tizen_profile = PassiveStackClassifier.infer_os_profile(
        ttl=64,
        window_size=29200,
        option55="1,3,6,15,28,33,43,119,121,252"
    )
    assert tizen_profile["os_profile"] == "TIZEN_OS"


def test_fingerprint_models_immutability():
    """Verify DeviceFingerprintRecord is frozen with dual mapping access."""
    rec = DeviceFingerprintRecord(
        ip="192.168.1.1",
        mac="00:11:22:33:44:55",
        vendor="Cisco Systems",
        type="router",
        model="Catalyst 9300"
    )
    assert rec["vendor"] == "Cisco Systems"
    assert rec.vendor == "Cisco Systems"
    assert "vendor" in rec
    assert rec.get("vendor") == "Cisco Systems"
    with pytest.raises(Exception):
        rec.vendor = "Other"


def test_device_fingerprinter_protocol_conformance():
    """Verify DeviceFingerprinter implements DeviceFingerprintPort."""
    from aetheris.discovery.fingerprint import DeviceFingerprinter
    prober = DeviceFingerprinter()
    assert isinstance(prober, DeviceFingerprintPort)

    res = prober.fingerprint(
        ip="192.168.1.50",
        mac="00:11:22:33:44:55",
        open_ports=[22, 80],
        banners={"22": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"},
        services=["ssh", "http"]
    )
    assert isinstance(res, DeviceFingerprintRecord)
    assert res.ip == "192.168.1.50"


def test_passive_stack_classifier_target_and_storage(tmp_path):
    """Verify PassiveStackClassifier classifies target and adheres to PassiveStackStoragePort."""
    from aetheris.core.ports.fingerprint_port import PassiveStackStoragePort
    db_file = tmp_path / "test_ledger.db"
    classifier = PassiveStackClassifier(db_path=str(db_file))
    assert isinstance(classifier, PassiveStackStoragePort)

    # Known telemetry lookup
    rec = classifier.classify_target("192.168.1.70")
    assert isinstance(rec, InferredOsProfileRecord)
    assert rec.os_profile == "WINDOWS_NT"
    assert rec["os_profile"] == "WINDOWS_NT"
    assert rec.confidence == 99.5

    # Fallback lookup
    rec2 = classifier.classify_target("10.0.0.99")
    assert isinstance(rec2, InferredOsProfileRecord)
    assert rec2.os_profile == "EMBEDDED_LINUX_STB"
    assert rec2.ip == "10.0.0.99"

    # Persistence verification
    classifier.save_profiles({"192.168.1.70": rec, "10.0.0.99": rec2})
    assert db_file.exists()

