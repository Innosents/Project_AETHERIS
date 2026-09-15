import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, Optional

class OuiRegistry:
    """
    In-memory OUI registry compiled from vendorMacs.xml.
    Provides O(1) vendor resolution and automated archetype classification.
    """
    _instance: Optional["OuiRegistry"] = None

    def __init__(self, xml_path: Optional[str] = None):
        if xml_path:
            self.xml_path = Path(xml_path)
        else:
            self.xml_path = Path(__file__).resolve().parent.parent.parent / "vendorMacs.xml"
        
        self.oui_table: Dict[str, str] = {}
        self._load()

    @classmethod
    def get_instance(cls) -> "OuiRegistry":
        if cls._instance is None:
            cls._instance = OuiRegistry()
        return cls._instance

    def _normalize_prefix(self, raw_prefix: str) -> str:
        return raw_prefix.upper().replace(":", "").replace("-", "").strip()

    def _load(self) -> None:
        if not self.xml_path.exists():
            return
        try:
            tree = ET.parse(self.xml_path)
            root = tree.getroot()
            # Handle XML namespaces dynamically
            for elem in root.iter():
                if elem.tag.endswith("VendorMapping"):
                    prefix = elem.attrib.get("mac_prefix")
                    vendor = elem.attrib.get("vendor_name")
                    if prefix and vendor:
                        clean_prefix = self._normalize_prefix(prefix)
                        self.oui_table[clean_prefix] = vendor.strip()
        except Exception:
            pass

    def lookup(self, mac: str) -> Optional[str]:
        clean_mac = self._normalize_prefix(mac)
        if len(clean_mac) < 6:
            return None
        return self.oui_table.get(clean_mac[:6])

    def infer_archetype(self, vendor: str) -> Dict[str, str]:
        """Maps registered vendor strings to MCMC archetypes and hardware categories."""
        v = vendor.lower()
        if any(w in v for w in ("cisco", "allied", "brocade", "extreme", "juniper", "nortel", "3com", "bay networks")):
            return {"archetype": "NETWORK_INFRASTRUCTURE", "type": "switch"}
        if any(w in v for w in ("rockwell", "schneider", "abb", "yokogawa", "honeywell", "omron", "siemens", "mercury")):
            return {"archetype": "INDUSTRIAL_OT", "type": "plc"}
        if any(w in v for w in ("axis", "mobotix", "hikvision", "dahua", "flir", "pelco")):
            return {"archetype": "CCTV_VIDEO", "type": "camera"}
        if any(w in v for w in ("apple", "samsung", "google", "roku", "technicolor", "humax", "foxconn", "lenovo", "microsoft")):
            return {"archetype": "CCTV_VIDEO" if any(m in v for m in ("roku", "technicolor", "humax")) else "WINDOWS_HOST", "type": "workstation" if any(m in v for m in ("foxconn", "lenovo", "microsoft")) else "endpoint"}
        return {"archetype": "GENERIC_HOST", "type": "unknown"}

