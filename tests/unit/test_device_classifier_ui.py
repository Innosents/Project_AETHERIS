"""
Unit Tests for DeviceClassifier classify_oui, EXTRA_OUIS, and UI Identity Label Formatting.
"""

import pytest
from graphpath.core.device_classifier import DeviceClassifier
from graphpath.cli.sweep import SubnetSweeper


def test_classify_oui_structured_hints():
    # 1. Samsung Smart TV
    samsung_tv = DeviceClassifier.classify_oui("38:01:95:AA:BB:CC")
    assert samsung_tv is not None
    assert samsung_tv["vendor"] == "Samsung Electronics"
    assert samsung_tv["type"] == "smart_tv"
    assert samsung_tv["os"] == "Tizen"

    # 2. Samsung Mobile Android
    samsung_mob = DeviceClassifier.classify_oui("5C:7D:7D:11:22:33")
    assert samsung_mob is not None
    assert samsung_mob["vendor"] == "Samsung Electronics"
    assert samsung_mob["type"] == "mobile"
    assert samsung_mob["os"] == "Android"

    # 3. Apple iOS
    apple = DeviceClassifier.classify_oui("10:78:5B:44:55:66")
    assert apple is not None
    assert apple["vendor"] == "Apple, Inc."
    assert apple["type"] == "mobile"
    assert apple["os"] == "iOS"

    # 4. Google Media Device
    google = DeviceClassifier.classify_oui("8C-6A-8D-77-88-99")
    assert google is not None
    assert google["vendor"] == "Google LLC"
    assert google["type"] == "media_device"
    assert google["os"] == "CastOS"

    # 5. Ubiquiti Network Infrastructure
    ubnt = DeviceClassifier.classify_oui("BC7E8B123456")
    assert ubnt is not None
    assert ubnt["vendor"] == "Ubiquiti Networks"
    assert ubnt["type"] == "network_infrastructure"
    assert ubnt["os"] == "UniFi"

    # 6. Technicolor STB
    stb = DeviceClassifier.classify_oui("9C:1E:95:99:AA:BB")
    assert stb is not None
    assert stb["vendor"] == "Technicolor / Vantiva"
    assert stb["type"] == "stb"
    assert stb["os"] == "Embedded Linux"

    # 7. Microsoft & Lenovo Workstations
    ms = DeviceClassifier.classify_oui("24:4B:FE:00:11:22")
    assert ms is not None
    assert ms["vendor"] == "Microsoft Corporation"
    assert ms["type"] == "workstation"

    lenovo = DeviceClassifier.classify_oui("1C:CE:51:AA:BB:CC")
    assert lenovo is not None
    assert lenovo["vendor"] == "Lenovo"
    assert lenovo["type"] == "workstation"

    # 8. Embedded RTOS
    rtos = DeviceClassifier.classify_oui("12:BA:5F:33:44:55")
    assert rtos is not None
    assert rtos["vendor"] == "Embedded RTOS"
    assert rtos["type"] == "iot_controller"
    assert rtos["os"] == "RTOS"

    # Unknown MAC
    assert DeviceClassifier.classify_oui("FA:FB:FC:00:00:00") is None
    assert DeviceClassifier.classify_oui("") is None


def test_device_classifier_classify_dna_enriches_os():
    classifier = DeviceClassifier()
    dna = {"mac": "38:01:95:11:22:33"}
    res = classifier.classify(dna)
    assert res["vendor"] == "Samsung Electronics"
    assert res["type"] == "smart_tv"
    assert res["os"] == "Tizen"
    assert res["os_family"] == "Tizen"


def test_format_device_identity_label():
    # Smart TV
    tv_label = SubnetSweeper._format_device_identity_label(
        device_type="smart_tv",
        vendor="Samsung Electronics",
        model="Samsung Smart TV",
        hostname="Living-Room-TV"
    )
    assert tv_label == "[SMART_TV] Samsung Smart TV (Living-Room-TV)"

    # Mobile iOS
    mob_label = SubnetSweeper._format_device_identity_label(
        device_type="mobile",
        vendor="Apple, Inc.",
        model="Apple iPhone/iPad",
        hostname=""
    )
    assert mob_label == "[MOBILE] Apple iPhone/iPad"

    # Access Control
    ac_label = SubnetSweeper._format_device_identity_label(
        device_type="access_control",
        vendor="Mercury Security",
        model="Mercury EP1502 Controller"
    )
    assert ac_label == "[ACCESS_CONTROL] Mercury EP1502 Controller"

    # Industrial OT
    iot_label = SubnetSweeper._format_device_identity_label(
        device_type="iot_controller",
        vendor="Embedded RTOS",
        model="Embedded RTOS Controller"
    )
    assert iot_label == "[INDUSTRIAL_OT] Embedded RTOS Controller"


def test_map_fingerprint_to_archetype_new_types():
    assert SubnetSweeper._map_fingerprint_to_archetype("iot_controller", "Embedded RTOS") == "INDUSTRIAL_OT"
    assert SubnetSweeper._map_fingerprint_to_archetype("network_infrastructure", "Ubiquiti Networks") == "NETWORK_INFRASTRUCTURE"
    assert SubnetSweeper._map_fingerprint_to_archetype("mobile", "Samsung Electronics", "Samsung Galaxy") == "WINDOWS_HOST"
    assert SubnetSweeper._map_fingerprint_to_archetype("stb", "Technicolor / Vantiva") == "CCTV_VIDEO"

