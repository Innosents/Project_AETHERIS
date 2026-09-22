"""Core OUI registry backed by an injected data-source port."""

from typing import Any, Dict, Optional

from aetheris.core.ports.oui_registry_port import (
    DeviceArchetypeProfile,
    OuiDataSourcePort,
    OuiRegistryPort,
)


class OuiRegistry(OuiRegistryPort):
    """In-memory OUI index with a backward-compatible XML source fallback."""

    _instance: Optional["OuiRegistry"] = None

    def __init__(
        self,
        xml_path: Optional[str] = None,
        data_source: Optional[OuiDataSourcePort] = None,
    ) -> None:
        if data_source is None:
            from aetheris.infrastructure.adapters.storage.oui_xml_adapter import (
                OuiXmlStorageAdapter,
            )

            data_source = OuiXmlStorageAdapter(xml_path=xml_path)
        self.data_source = data_source
        self.xml_path = getattr(data_source, "xml_path", xml_path)
        self.oui_table: Dict[str, str] = {}
        self._load()

    @classmethod
    def get_instance(cls) -> "OuiRegistry":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def normalize_prefix(self, raw: str) -> str:
        return str(raw or "").upper().replace(":", "").replace("-", "").strip()

    def _normalize_prefix(self, raw_prefix: str) -> str:
        return self.normalize_prefix(raw_prefix)

    def _load(self) -> None:
        try:
            records = self.data_source.load_oui_records()
            for prefix, vendor in records.items():
                normalized_prefix = self.normalize_prefix(prefix)
                if normalized_prefix and vendor:
                    self.oui_table[normalized_prefix] = str(vendor).strip()
        except Exception:
            pass

    def lookup(self, mac_or_prefix: str) -> Optional[str]:
        clean_mac = self.normalize_prefix(mac_or_prefix)
        if len(clean_mac) < 6:
            return None
        return self.oui_table.get(clean_mac[:6])

    def is_known_vendor(self, mac: str) -> bool:
        return self.lookup(mac) is not None

    def infer_archetype(self, vendor: str) -> Dict[str, str]:
        """Map registered vendor strings to hardware operational archetypes."""
        value = vendor.lower()
        if any(word in value for word in ("cisco", "allied", "brocade", "extreme", "juniper", "nortel", "3com", "bay networks")):
            profile = DeviceArchetypeProfile(archetype="NETWORK_INFRASTRUCTURE", type="switch")
            return profile.model_dump()
        if any(word in value for word in ("rockwell", "schneider", "abb", "yokogawa", "honeywell", "omron", "siemens", "mercury")):
            profile = DeviceArchetypeProfile(archetype="INDUSTRIAL_OT", type="plc")
            return profile.model_dump()
        if any(word in value for word in ("axis", "mobotix", "hikvision", "dahua", "flir", "pelco")):
            profile = DeviceArchetypeProfile(archetype="CCTV_VIDEO", type="camera")
            return profile.model_dump()
        if any(word in value for word in ("apple", "samsung", "google", "roku", "technicolor", "humax", "foxconn", "lenovo", "microsoft")):
            profile = DeviceArchetypeProfile(
                archetype="CCTV_VIDEO" if any(word in value for word in ("roku", "technicolor", "humax")) else "WINDOWS_HOST",
                type="workstation" if any(word in value for word in ("foxconn", "lenovo", "microsoft")) else "endpoint",
            )
            return profile.model_dump()
        profile = DeviceArchetypeProfile(archetype="GENERIC_HOST", type="unknown")
        return profile.model_dump()


__all__ = ["OuiRegistry"]
