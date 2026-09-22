"""
Unit tests for OuiRegistry and vendorMacs.xml integration.
Validates XML parsing, namespace handling, OUI prefix normalization,
O(1) lookup, archetype inference, and integration with DeviceClassifier.
"""

import tempfile
import os
import pytest
from aetheris.core.oui_registry import OuiRegistry
from aetheris.core.device_classifier import DeviceClassifier


SAMPLE_VENDOR_MACS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<VendorMappings xmlns="http://schemas.datacontract.org/2004/07/DeviceClassifier">
    <VendorMapping mac_prefix="00:00:0C" vendor_name="Cisco Systems, Inc" />
    <VendorMapping mac_prefix="00-01-42" vendor_name="Cisco Systems" />
    <VendorMapping mac_prefix="001D9C" vendor_name="Rockwell Automation" />
    <VendorMapping mac_prefix="00408C" vendor_name="Axis Communications AB" />
    <VendorMapping mac_prefix="000D4B" vendor_name="Roku, Inc." />
    <VendorMapping mac_prefix="0017F2" vendor_name="Apple, Inc." />
    <VendorMapping mac_prefix="0026B9" vendor_name="Dell Inc." />
</VendorMappings>
"""


def test_oui_registry_xml_parsing_and_lookup():
    with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", encoding="utf-8", delete=False) as tf:
        tf.write(SAMPLE_VENDOR_MACS_XML)
        temp_xml_path = tf.name

    try:
        registry = OuiRegistry(xml_path=temp_xml_path)
        assert len(registry.oui_table) >= 7

        # Test colon-delimited lookup
        assert registry.lookup("00:00:0C:11:22:33") == "Cisco Systems, Inc"

        # Test dash-delimited lookup
        assert registry.lookup("00-01-42-AA-BB-CC") == "Cisco Systems"

        # Test raw hex lookup
        assert registry.lookup("001D9C998877") == "Rockwell Automation"

        # Test non-existent OUI
        assert registry.lookup("FFFFFF001122") is None

        # Test short/invalid MAC
        assert registry.lookup("0011") is None
    finally:
        if os.path.exists(temp_xml_path):
            os.remove(temp_xml_path)


def test_oui_registry_archetype_inference():
    registry = OuiRegistry()

    # Cisco -> Network Infrastructure Switch
    cisco_arch = registry.infer_archetype("Cisco Systems, Inc")
    assert cisco_arch["archetype"] == "NETWORK_INFRASTRUCTURE"
    assert cisco_arch["type"] == "switch"

    # Rockwell / Schneider -> Industrial OT PLC
    plc_arch = registry.infer_archetype("Rockwell Automation")
    assert plc_arch["archetype"] == "INDUSTRIAL_OT"
    assert plc_arch["type"] == "plc"

    # Axis -> CCTV Video Camera
    cam_arch = registry.infer_archetype("Axis Communications AB")
    assert cam_arch["archetype"] == "CCTV_VIDEO"
    assert cam_arch["type"] == "camera"

    # Roku -> CCTV Video (Media device)
    roku_arch = registry.infer_archetype("Roku, Inc.")
    assert roku_arch["archetype"] == "CCTV_VIDEO"
    assert roku_arch["type"] == "endpoint"

    # Apple -> Windows Host (Interactive endpoint)
    apple_arch = registry.infer_archetype("Apple, Inc.")
    assert apple_arch["archetype"] == "WINDOWS_HOST"
    assert apple_arch["type"] == "endpoint"

    # Dell -> Generic Host
    generic_arch = registry.infer_archetype("Dell Inc.")
    assert generic_arch["archetype"] == "GENERIC_HOST"


def test_device_classifier_oui_registry_fallback():
    with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", encoding="utf-8", delete=False) as tf:
        tf.write(SAMPLE_VENDOR_MACS_XML)
        temp_xml_path = tf.name

    try:
        # Re-initialize singleton with mock XML
        OuiRegistry._instance = OuiRegistry(xml_path=temp_xml_path)

        # Lookup OUI that is in XML: 0026B9 (Dell Inc.)
        hint = DeviceClassifier.classify_oui("00:26:B9:12:34:56")
        assert hint is not None
        assert hint["vendor"] == "Dell Inc."

        # Classify device DNA
        dna = {"mac": "00:26:B9:12:34:56", "ip": "192.168.1.50"}
        classified = DeviceClassifier().classify(dna)
        assert classified["vendor"] == "Dell Inc."
        assert classified["model"] == "Dell Inc. Device"
    finally:
        OuiRegistry._instance = None
        if os.path.exists(temp_xml_path):
            os.remove(temp_xml_path)

