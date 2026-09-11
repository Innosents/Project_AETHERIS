"""
GraphPath Core Device Classifier & OUI Identification Engine.
"""
from typing import Dict, Any

class DeviceClassifier:
    """Classifies device DNA and provides Hardware OUI lookups."""

    OUI_DB: Dict[str, Dict[str, str]] = {
        "000C29": {"vendor": "VMware, Inc.", "type": "server", "model": "VMware Virtual Machine"},
        "005056": {"vendor": "VMware, Inc.", "type": "server", "model": "VMware Virtual Machine"},
        "B827EB": {"vendor": "Raspberry Pi Foundation", "type": "iot", "model": "Raspberry Pi Single-Board Computer"},
        "DCA632": {"vendor": "Raspberry Pi Foundation", "type": "iot", "model": "Raspberry Pi 4 / Compute Module"},
        "E45F01": {"vendor": "Raspberry Pi Foundation", "type": "iot", "model": "Raspberry Pi 4B / 400"},
        "28CDC4": {"vendor": "Raspberry Pi Foundation", "type": "iot", "model": "Raspberry Pi 5"},
        "001788": {"vendor": "Signify Netherlands B.V.", "type": "iot", "model": "Philips Hue Bridge"},
        "0004F2": {"vendor": "Polycom", "type": "voip_phone", "model": "Polycom SoundPoint / VVX Phone"},
        "000B82": {"vendor": "Grandstream Networks", "type": "voip_phone", "model": "Grandstream IP Telephony"},
        "805E0C": {"vendor": "Yealink Network", "type": "voip_phone", "model": "Yealink SIP Phone"},
        "00408C": {"vendor": "Axis Communications", "type": "camera", "model": "AXIS Network Camera"},
        "ACCC8E": {"vendor": "Axis Communications", "type": "camera", "model": "AXIS Security Device"},
        "001D9C": {"vendor": "Rockwell Automation", "type": "plc", "model": "Allen-Bradley PLC/PAC"},
        "000E8C": {"vendor": "Siemens AG", "type": "plc", "model": "Siemens SIMATIC S7 Controller"},
        "0080F4": {"vendor": "Schneider Electric", "type": "plc", "model": "Telemecanique / Modicon PLC"},
        "00000C": {"vendor": "Cisco Systems", "type": "switch", "model": "Cisco Enterprise Infrastructure"},
        "000142": {"vendor": "Cisco Systems", "type": "switch", "model": "Cisco Catalyst Switch"},
        "70DA48": {"vendor": "Ubiquiti Networks", "type": "router", "model": "UniFi Security Gateway / Dream Machine"},
        "B4FBE4": {"vendor": "Ubiquiti Networks", "type": "wlan_ap", "model": "UniFi Access Point"},
        "000F9F": {"vendor": "Mercury Security", "type": "access_control", "model": "Mercury EP / LP Access Panel"},
    }

    def classify(self, device_dna: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(device_dna)
        mac = str(device_dna.get("mac", "")).replace(":", "").replace("-", "").upper()[:6]

        if mac in self.OUI_DB:
            oui_match = self.OUI_DB[mac]
            if result.get("vendor") in (None, "", "Unknown Vendor", "generic"):
                result["vendor"] = oui_match["vendor"]
            if result.get("type") in (None, "", "unknown", "generic"):
                result["type"] = oui_match["type"]
            if result.get("model") in (None, "", "Generic Device", "Network Endpoint"):
                result["model"] = oui_match["model"]

        return result