from typing import Dict, Any, Optional
from graphpath.core.oui_registry import OuiRegistry

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
        # Apple (iPhones, iPads, Apple TVs, MacBooks)
        "0017F2": {"vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iOS Device"},
        "ACBC32": {"vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iOS Device"},
        "F01898": {"vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iOS Device"},
        "F4F15A": {"vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iOS Device"},
        "3C0754": {"vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iOS Device"},
        "F8FFC2": {"vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iOS Device"},
        # Samsung Electronics (Smart TVs)
        "0007AB": {"vendor": "Samsung Electronics", "type": "smart_tv", "model": "Samsung Smart TV"},
        "BC4486": {"vendor": "Samsung Electronics", "type": "smart_tv", "model": "Samsung Smart TV"},
        "F4428F": {"vendor": "Samsung Electronics", "type": "smart_tv", "model": "Samsung Smart TV"},
        "D003DF": {"vendor": "Samsung Electronics", "type": "smart_tv", "model": "Samsung Smart TV"},
        # Roku Streaming Devices
        "000D4B": {"vendor": "Roku Inc.", "type": "media_device", "model": "Roku Streaming Device"},
        "AC3A7A": {"vendor": "Roku Inc.", "type": "media_device", "model": "Roku Streaming Device"},
        "D83134": {"vendor": "Roku Inc.", "type": "media_device", "model": "Roku Streaming Device"},
        "B0A737": {"vendor": "Roku Inc.", "type": "media_device", "model": "Roku Streaming Device"},
        # Google (Android / Chromecast)
        "001A11": {"vendor": "Google LLC", "type": "mobile_android", "model": "Android Mobile Device"},
        "F4F5E8": {"vendor": "Google LLC", "type": "mobile_android", "model": "Android Mobile Device"},
        "D86C63": {"vendor": "Google LLC", "type": "mobile_android", "model": "Android Mobile Device"},
        # Amazon (Fire TV / Echo)
        "00FC8B": {"vendor": "Amazon", "type": "media_device", "model": "Amazon Fire TV Device"},
        "FC65DE": {"vendor": "Amazon", "type": "media_device", "model": "Amazon Fire TV Device"},
        "44650D": {"vendor": "Amazon", "type": "media_device", "model": "Amazon Fire TV Device"},
        # ARRIS / CommScope Set-Top Boxes
        "0015A2": {"vendor": "ARRIS / CommScope", "type": "stb", "model": "ARRIS IPTV Set-Top Box"},
        "5819F8": {"vendor": "ARRIS / CommScope", "type": "stb", "model": "ARRIS IPTV Set-Top Box"},
        # Technicolor Set-Top Boxes
        "001CD4": {"vendor": "Technicolor", "type": "stb", "model": "Technicolor Android TV STB"},
        "A41588": {"vendor": "Technicolor", "type": "stb", "model": "Technicolor Android TV STB"},
        # HID Global (Access Control Panels)
        "00068E": {"vendor": "HID Global", "type": "access_control", "model": "HID Aero Access Controller"},
        # Additional Consumer & Infrastructure OUIs
        "380195": {"vendor": "Samsung Electronics", "type": "smart_tv", "os": "Tizen", "model": "Samsung Smart TV (Tizen)"},
        "5C7D7D": {"vendor": "Samsung Electronics", "type": "mobile", "os": "Android", "model": "Samsung Galaxy Device"},
        "10785B": {"vendor": "Apple, Inc.", "type": "mobile", "os": "iOS", "model": "Apple iPhone/iPad"},
        "D4B92F": {"vendor": "Vantiva USA LLC", "type": "stb", "os": "Linux", "model": "Technicolor / Cisco IPTV STB"},
        "D4E22F": {"vendor": "Roku, Inc.", "type": "media_device", "os": "Roku OS", "model": "Roku Streaming Player"},
        "8C6A8D": {"vendor": "Google LLC", "type": "media_device", "os": "CastOS", "model": "Google Chromecast / Nest"},
        "BC7E8B": {"vendor": "Ubiquiti Networks", "type": "network_infrastructure", "os": "UniFi", "model": "UniFi Device"},
        "9C1E95": {"vendor": "Technicolor / Vantiva", "type": "stb", "os": "Embedded Linux", "model": "Technicolor 4K STB"},
        "244BFE": {"vendor": "Microsoft Corporation", "type": "workstation", "os": "Windows", "model": "Microsoft Surface / Windows Host"},
        "1CCE51": {"vendor": "Lenovo", "type": "workstation", "os": "Windows", "model": "Lenovo ThinkPad / ThinkCentre"},
        "12BA5F": {"vendor": "Embedded RTOS", "type": "iot_controller", "os": "RTOS", "model": "Embedded RTOS Controller"},
        "28EA0B": {"vendor": "Foxconn", "type": "workstation", "os": "Windows", "model": "Foxconn / Windows Workstation"},
        "001E65": {"vendor": "Foxconn", "type": "workstation", "os": "Windows", "model": "Foxconn / Windows Workstation"},
    }

    @classmethod
    def classify_oui(cls, mac: str) -> Optional[Dict[str, Any]]:
        """Extracts structured vendor, type, and OS hints from a MAC address OUI prefix."""
        clean_mac = str(mac or "").replace(":", "").replace("-", "").upper()[:6]
        if clean_mac in cls.OUI_DB:
            return dict(cls.OUI_DB[clean_mac])
        
        # Fallback to XML-backed OuiRegistry
        vendor = OuiRegistry.get_instance().lookup(clean_mac)
        if vendor:
            inferred = OuiRegistry.get_instance().infer_archetype(vendor)
            return {
                "vendor": vendor,
                "type": inferred.get("type", "unknown"),
                "model": f"{vendor} Device",
                "archetype": inferred.get("archetype", "GENERIC_HOST")
            }
        return None

    # Cable Category & Hardware Nominal Velocity of Propagation Mapping
    NVP_PROFILE_MAP: Dict[str, float] = {
        # High-power PoE+ / Modern IP Video Surveillance (Cat6/Cat6a, NVP ~ 0.70)
        "camera": 0.70,
        "cctv": 0.70,
        "ip_camera": 0.70,
        "axis": 0.70,
        "hikvision": 0.70,
        "dahua": 0.70,
        "hanwha": 0.70,
        # Industrial Automation & Legacy PLCs (Cat5/Cat5e, NVP ~ 0.68)
        "plc": 0.68,
        "industrial": 0.68,
        "iot_controller": 0.68,
        "access_control": 0.68,
        "siemens": 0.68,
        "rockwell": 0.68,
        "schneider": 0.68,
        "allen-bradley": 0.68,
        "modicon": 0.68,
        "mercury": 0.68,
        # Legacy / Standard VoIP Endpoints (Cat5e, NVP ~ 0.68)
        "voip_phone": 0.68,
        "ip_phone": 0.68,
        "polycom": 0.68,
        "grandstream": 0.68,
        "yealink": 0.68,
        # High-Performance Infrastructure & Datacenter (Cat6a/Cat7, NVP ~ 0.70-0.72)
        "switch": 0.70,
        "router": 0.70,
        "cisco": 0.70,
        "ubiquiti": 0.70,
        "server": 0.72,
        "vmware": 0.72,
    }

    @classmethod
    def resolve_nvp(
        cls,
        mac: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        default_nvp: float = 0.69,
    ) -> float:
        """
        Resolves the dynamic Nominal Velocity of Propagation (NVP) based on hardware MAC OUI,
        vendor profile, and device archetype. Falls back to default_nvp (0.69) if ambiguous.
        """
        inferred_vendor = None
        inferred_type = None
        if mac:
            oui_info = cls.classify_oui(mac)
            if oui_info:
                inferred_vendor = oui_info.get("vendor")
                inferred_type = oui_info.get("type")

        candidates = [
            device_type,
            inferred_type,
            vendor,
            inferred_vendor,
        ]

        for candidate in candidates:
            if not candidate:
                continue
            cand_clean = str(candidate).lower().strip()
            for key, nvp_val in cls.NVP_PROFILE_MAP.items():
                if key in cand_clean:
                    return nvp_val

        return default_nvp

    def classify(self, device_dna: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(device_dna)
        mac = str(device_dna.get("mac", "")).replace(":", "").replace("-", "").upper()[:6]

        oui_match = None
        if mac in self.OUI_DB:
            oui_match = self.OUI_DB[mac]
        else:
            vendor = OuiRegistry.get_instance().lookup(mac)
            if vendor:
                inferred = OuiRegistry.get_instance().infer_archetype(vendor)
                oui_match = {
                    "vendor": vendor,
                    "type": inferred.get("type", "unknown"),
                    "model": f"{vendor} Device"
                }

        if oui_match:
            if result.get("vendor") in (None, "", "Unknown Vendor", "generic"):
                result["vendor"] = oui_match["vendor"]
            if result.get("type") in (None, "", "unknown", "generic"):
                result["type"] = oui_match["type"]
            if result.get("model") in (None, "", "Generic Device", "Network Endpoint"):
                result["model"] = oui_match.get("model", f"{oui_match['vendor']} Endpoint")
            if "os" in oui_match and not result.get("os"):
                result["os"] = oui_match["os"]
            if "os" in oui_match and not result.get("os_family"):
                result["os_family"] = oui_match["os"]

        return result