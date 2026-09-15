"""
Unit Tests for DeviceClassifier
Validates MAC OUI resolution, normalization across delimiter styles,
preservation of specific metadata, and unknown hardware fallbacks.
"""

import pytest
from graphpath.core.device_classifier import DeviceClassifier


def test_device_classifier_vmware_oui():
    classifier = DeviceClassifier()
    dna = {
        "ip": "192.168.1.10",
        "mac": "00:0C:29:AA:BB:CC",
        "vendor": None,
        "type": "unknown",
        "model": "Generic Device"
    }
    result = classifier.classify(dna)
    assert result["vendor"] == "VMware, Inc."
    assert result["type"] == "server"
    assert result["model"] == "VMware Virtual Machine"


def test_device_classifier_mac_delimiter_formats():
    classifier = DeviceClassifier()
    # Test hyphens, lowercase, and no delimiters for Raspberry Pi (B827EB)
    mac_variants = [
        "b8:27:eb:12:34:56",
        "B8-27-EB-12-34-56",
        "b827eb123456"
    ]
    for mac in mac_variants:
        dna = {"mac": mac}
        result = classifier.classify(dna)
        assert result["vendor"] == "Raspberry Pi Foundation"
        assert result["type"] == "iot"
        assert "Raspberry Pi" in result["model"]


def test_device_classifier_preserves_specific_existing_metadata():
    classifier = DeviceClassifier()
    dna = {
        "mac": "00:00:0C:11:22:33",  # Cisco OUI
        "vendor": "Custom Cisco OEM",
        "type": "custom_switch",
        "model": "Catalyst 9300 Custom"
    }
    result = classifier.classify(dna)
    # Existing explicit/specific values must NOT be overwritten
    assert result["vendor"] == "Custom Cisco OEM"
    assert result["type"] == "custom_switch"
    assert result["model"] == "Catalyst 9300 Custom"


def test_device_classifier_overwrites_generic_placeholders():
    classifier = DeviceClassifier()
    dna = {
        "mac": "00:40:8C:99:88:77",  # Axis Communications
        "vendor": "Unknown Vendor",
        "type": "generic",
        "model": "Network Endpoint"
    }
    result = classifier.classify(dna)
    assert result["vendor"] == "Axis Communications"
    assert result["type"] == "camera"
    assert result["model"] == "AXIS Network Camera"


def test_device_classifier_industrial_plc_oui():
    classifier = DeviceClassifier()
    # Rockwell Automation (001D9C)
    dna = {"mac": "00:1D:9C:55:66:77"}
    result = classifier.classify(dna)
    assert result["vendor"] == "Rockwell Automation"
    assert result["type"] == "plc"
    assert "Allen-Bradley" in result["model"]


def test_device_classifier_unknown_or_missing_mac():
    classifier = DeviceClassifier()
    
    # Unknown OUI
    dna_unknown = {"mac": "FA:FB:FC:11:22:33", "vendor": "Unchanged"}
    res_unknown = classifier.classify(dna_unknown)
    assert res_unknown["vendor"] == "Unchanged"
    assert "type" not in res_unknown

    # Missing / empty MAC
    dna_empty = {"vendor": "Existing"}
    res_empty = classifier.classify(dna_empty)
    assert res_empty["vendor"] == "Existing"

