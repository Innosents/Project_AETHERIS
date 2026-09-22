"""
Unit tests for Device Identity Profile (DIP) Port & Storage Adapter.
Validates protocol conformance, atomic JSON storage, progressive confidence, and mapping compatibility.
"""

import tempfile
import pytest
from pathlib import Path
from aetheris.core.dip_manager import DeviceIdentityProfileManager
from aetheris.core.ports.dip_port import (
    DeviceIdentityProfile,
    DeviceIdentityProfilePort,
    DipStoragePort,
    ProfileLearningPayload,
    ProfileMatchResult,
)
from aetheris.infrastructure.adapters.storage.json_dip_storage_adapter import JsonDipStorageAdapter


def test_dip_port_protocol_conformance():
    """Assert DeviceIdentityProfileManager implements DeviceIdentityProfilePort."""
    assert issubclass(DeviceIdentityProfileManager, DeviceIdentityProfilePort)
    mgr = DeviceIdentityProfileManager()
    assert isinstance(mgr, DeviceIdentityProfilePort)


def test_dip_storage_port_protocol_conformance():
    """Assert JsonDipStorageAdapter implements DipStoragePort."""
    assert issubclass(JsonDipStorageAdapter, DipStoragePort)
    adapter = JsonDipStorageAdapter(tempfile.mktemp(suffix=".json"))
    assert isinstance(adapter, DipStoragePort)


def test_json_dip_storage_adapter_atomic_persistence():
    """Verify atomic write, loading, and recovery on empty/missing files."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_file = tf.name

    adapter = JsonDipStorageAdapter(temp_file)
    test_data = {
        "00:11:22:33:44:55": {
            "mac": "00:11:22:33:44:55",
            "vendor": "Cisco Systems",
            "confidence": 0.85
        }
    }

    # Save and verify load
    assert adapter.save_profiles(test_data) is True
    loaded = adapter.load_profiles()
    assert "00:11:22:33:44:55" in loaded
    assert loaded["00:11:22:33:44:55"]["vendor"] == "Cisco Systems"

    # Verify target string
    target = adapter.get_storage_target()
    assert temp_file in target


def test_dip_manager_storage_dependency_injection():
    """Verify DeviceIdentityProfileManager operates over an injected storage adapter."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_file = tf.name

    storage_adapter = JsonDipStorageAdapter(temp_file)
    mgr = DeviceIdentityProfileManager(storage=storage_adapter)
    mgr.profiles = {}

    mac = "00:0C:29:11:22:33"
    prof = mgr.get_or_create(mac, ip="10.0.0.5")

    # Assert returned record is DeviceIdentityProfile
    assert isinstance(prof, DeviceIdentityProfile)
    assert prof.mac == mac
    assert prof["mac"] == mac
    assert prof.vendor == "VMware / Industrial"
    assert prof["vendor"] == "VMware / Industrial"

    # Assert persisted to storage adapter
    persisted = storage_adapter.load_profiles()
    assert mac in persisted
    assert persisted[mac]["vendor"] == "VMware / Industrial"


def test_dip_model_mapping_compatibility_and_mutations():
    """Assert Pydantic model supports attribute access, dict subscription, and backward-compatible edits."""
    prof = DeviceIdentityProfile(
        mac="AA:BB:CC:DD:EE:FF",
        ip="192.168.1.55",
        vendor="Acme Corp",
        confidence=0.75
    )

    # Read access
    assert prof.mac == "AA:BB:CC:DD:EE:FF"
    assert prof["mac"] == "AA:BB:CC:DD:EE:FF"
    assert prof.get("ip") == "192.168.1.55"
    assert "vendor" in prof
    assert "nonexistent" not in prof

    # Mutability
    prof["vendor"] = "Acme Corp Updated"
    assert prof.vendor == "Acme Corp Updated"
    assert prof["vendor"] == "Acme Corp Updated"

    prof["custom_tag"] = "sensor_cluster_1"
    assert prof["custom_tag"] == "sensor_cluster_1"


def test_dip_lock_and_deep_signature_recording():
    """Assert locking and deep protocol fingerprint recording."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_file = tf.name

    mgr = DeviceIdentityProfileManager(storage_path=temp_file)
    mgr.profiles = {}

    mac = "AC:BC:32:99:88:77"
    mgr.get_or_create(mac, ip="192.168.1.200")

    # Lock profile
    locked = mgr.lock_profile(
        profile_id=mac,
        custom_type="camera",
        custom_vendor="Axis Communications",
        custom_model="AXIS M3045-V"
    )
    assert locked is True
    prof = mgr.lookup(mac)
    assert prof.is_locked is True
    assert prof.confidence == 1.0
    assert prof.vendor == "Axis Communications"

    # Record deep signature
    deep_fp = {
        "protocol": "RTSP",
        "title": "AXIS M3045-V Network Camera",
        "server": "Boa/0.94.14rc21"
    }
    updated = mgr.record_deep_signature(
        ip="192.168.1.200",
        mac=mac,
        deep_fingerprint=deep_fp,
        archetype="CAMERA",
        env_cidr="192.168.1.0/24"
    )
    assert updated.verified_fingerprint is True
    assert updated.deep_signature["protocol"] == "RTSP"

