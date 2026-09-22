"""XML-backed adapter for IEEE OUI vendor data."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Optional

from aetheris.core.ports.oui_registry_port import OuiDataSourcePort


class OuiXmlStorageAdapter(OuiDataSourcePort):
    """Loads VendorMapping records from vendorMacs.xml."""

    def __init__(self, xml_path: Optional[str] = None) -> None:
        self.xml_path = (
            Path(xml_path)
            if xml_path
            else Path(__file__).resolve().parents[4] / "vendorMacs.xml"
        )

    def load_oui_records(self) -> Dict[str, str]:
        if not self.xml_path.exists():
            return {}
        try:
            tree = ET.parse(self.xml_path)
            records: Dict[str, str] = {}
            for element in tree.getroot().iter():
                if not element.tag.endswith("VendorMapping"):
                    continue
                prefix = element.attrib.get("mac_prefix")
                vendor = element.attrib.get("vendor_name")
                if prefix and vendor:
                    records[prefix] = vendor.strip()
            return records
        except Exception:
            return {}


__all__ = ["OuiXmlStorageAdapter"]
