"""
Unit tests for DeviceClassifier and DeviceClassifierPort hexagonal contract.
Validates AST purity, Pydantic model behavior, OUI resolution, and NVP physics bounds.
"""

import pytest
from aetheris.core.device_classifier import DeviceClassifier
from aetheris.core.ports.device_classifier_port import (
    DeviceClassificationResult,
    DeviceClassifierPort,
    DeviceDna,
    OuiClassificationResult,
)


def test_device_classifier_port_protocol_conformance():
    """Verify DeviceClassifier conforms to the DeviceClassifierPort Protocol."""
    assert issubclass(DeviceClassifier, DeviceClassifierPort)
    classifier = DeviceClassifier()
    assert isinstance(classifier, DeviceClassifierPort)


def test_pydantic_mapping_compatibility_and_immutability():
    """Verify mapping surface, immutability of declared fields, and mutable extra fields."""
    dna = DeviceDna(mac="00:0C:29:AA:BB:CC", ip="192.168.1.50")
    
    # Dual access: attribute and dictionary indexing
    assert dna.mac == "00:0C:29:AA:BB:CC"
    assert dna["mac"] == "00:0C:29:AA:BB:CC"
    assert dna.get("ip") == "192.168.1.50"
    assert "mac" in dna
    assert "ip" in dna
    assert "type" not in dna

    # Declared fields are frozen
    with pytest.raises(TypeError, match="Declared device classification fields are immutable"):
        dna["mac"] = "00:11:22:33:44:55"

    # Undeclared fields can be enriched dynamically
    dna["extra_tag"] = "datacenter_cluster_a"
    assert dna["extra_tag"] == "datacenter_cluster_a"
    assert "extra_tag" in dna


def test_device_classifier_vmware_resolution():
    """Assert VMware OUI resolution returns typed OuiClassificationResult and DeviceClassificationResult."""
    classifier = DeviceClassifier()
    dna = {
        "ip": "192.168.1.10",
        "mac": "00:0C:29:AA:BB:CC",
        "vendor": None,
        "type": "unknown",
        "model": "Generic Device",
    }
    result = classifier.classify(dna)
    assert isinstance(result, DeviceClassificationResult)
    assert result.vendor == "VMware, Inc."
    assert result["vendor"] == "VMware, Inc."
    assert result.type == "server"
    assert result.model == "VMware Virtual Machine"


def test_device_classifier_delimiter_robustness():
    """Assert MAC delimiter variants (colon, hyphen, bare hex, lower/upper) resolve identically."""
    classifier = DeviceClassifier()
    variants = [
        "b8:27:eb:12:34:56",
        "B8-27-EB-12-34-56",
        "b827eb123456",
        "B827EB123456",
    ]
    for mac in variants:
        res = classifier.classify_oui(mac)
        assert isinstance(res, OuiClassificationResult)
        assert res.vendor == "Raspberry Pi Foundation"
        assert res.type == "iot"
        assert "Raspberry Pi" in res.model


def test_nvp_bounds_and_physics_invariants():
    """
    Assert all NVP entries in NVP_PROFILE_MAP are strictly within [0.68, 0.72]
    to bound electromagnetic propagation velocities for spatial deconvolution.
    """
    for profile, nvp in DeviceClassifier.NVP_PROFILE_MAP.items():
        assert 0.68 <= nvp <= 0.72, f"Profile '{profile}' has out-of-bounds NVP: {nvp}"

    # Default fallback
    assert DeviceClassifier.resolve_nvp() == 0.69

    # Specific profile lookups
    assert DeviceClassifier.resolve_nvp(mac="00:0C:29:11:22:33") == 0.72  # VMware server
    assert DeviceClassifier.resolve_nvp(mac="00:0E:8C:11:22:33") == 0.68  # Siemens PLC
    assert DeviceClassifier.resolve_nvp(device_type="ip_camera") == 0.70  # Surveillance PoE+
    assert DeviceClassifier.resolve_nvp(vendor="Allen-Bradley") == 0.68   # Industrial PLC


def test_metadata_preservation_and_placeholder_overwrites():
    """Assert explicit custom metadata is preserved while generic placeholders are overwritten."""
    classifier = DeviceClassifier()

    # Explicit metadata preserved
    explicit_dna = {
        "mac": "00:00:0C:11:22:33",  # Cisco OUI
        "vendor": "Custom Cisco OEM",
        "type": "custom_switch",
        "model": "Catalyst 9300 Custom",
    }
    res_explicit = classifier.classify(explicit_dna)
    assert res_explicit.vendor == "Custom Cisco OEM"
    assert res_explicit.type == "custom_switch"
    assert res_explicit.model == "Catalyst 9300 Custom"

    # Generic placeholder overwritten
    generic_dna = {
        "mac": "00:40:8C:99:88:77",  # Axis Communications
        "vendor": "Unknown Vendor",
        "type": "generic",
        "model": "Network Endpoint",
    }
    res_generic = classifier.classify(generic_dna)
    assert res_generic.vendor == "Axis Communications"
    assert res_generic.type == "camera"
    assert res_generic.model == "AXIS Network Camera"


def test_unknown_or_missing_mac_fallback():
    """Assert unknown or missing MACs do not crash and leave existing metadata intact."""
    classifier = DeviceClassifier()

    # Unknown OUI
    dna_unknown = {"mac": "FA:FB:FC:11:22:33", "vendor": "Unchanged"}
    res_unknown = classifier.classify(dna_unknown)
    assert res_unknown.vendor == "Unchanged"
    assert "type" not in res_unknown

    # Missing MAC
    dna_empty = {"vendor": "Existing"}
    res_empty = classifier.classify(dna_empty)
    assert res_empty.vendor == "Existing"
    assert res_empty.mac is None

