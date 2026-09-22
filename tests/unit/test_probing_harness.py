import pytest
from aetheris.discovery.dpi_parser import DpiParser
from aetheris.core.dip_manager import DeviceIdentityProfileManager

def test_passive_dpi_feed_into_dip(tmp_path):
    dip_file = tmp_path / "test_dip.json"
    mgr = DeviceIdentityProfileManager(storage_path=str(dip_file))
    dpi = DpiParser()

    # Synthetic DHCP ACK frame with Option 12 (Client Name) and Option 60
    synthetic_payload = {
        "mac": "12:E6:D6:E7:52:CE",
        "ip": "192.168.1.75",
        "hostname": "James-Phone",
        "vendor": "Apple Inc.",
        "model": "iPhone 15 Pro",
        "dev_type": "mobile_ios",
        "os_family": "iOS"
    }

    mgr.ingest_observation(**synthetic_payload)
    profile = mgr.lookup("12:E6:D6:E7:52:CE")

    assert profile is not None
    assert profile["hostname"] == "James-Phone"
    assert profile["model"] == "iPhone 15 Pro"
    assert profile["confidence"] >= 0.90