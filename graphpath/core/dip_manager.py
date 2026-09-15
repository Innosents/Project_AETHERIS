"""
Project AETHERIS - Device Identity Profile (DIP) Manager
Dynamic identity caching, learning, and environmental cross-referencing engine.
Persists high-confidence device fingerprints across sweeps and environments
so familiar laptops, phones, STBs, and TVs are immediately recognized and never reset to unknown.
"""

import os
import json
import time
import re
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from graphpath.core.oui_registry import OuiRegistry

BLACKLIST_TITLES = {
    "404 - not found", "404 not found", "not found", "403 forbidden",
    "401 unauthorized", "500 internal server error", "index of /",
    "web server", "accueil", "default", "bad request"
}

IEEE_OUI_MAP = {
    "00270D": {"vendor": "Cisco Systems", "type": "switch", "os": "Cisco IOS"},
    "001122": {"vendor": "Network Switch", "type": "switch", "os": "Embedded"},
    "000C29": {"vendor": "VMware / Industrial", "type": "plc", "os": "RTOS"},
    "000F9F": {"vendor": "Mercury Security", "type": "access_control", "os": "Embedded Linux", "model": "Mercury MP1502 Controller"},
    "ACBC32": {"vendor": "Apple Inc.", "type": "mobile_ios", "os": "iOS"},
    "10785B": {"vendor": "Apple Inc.", "type": "mobile_ios", "os": "iOS"},
    "D4B92F": {"vendor": "Apple Inc.", "type": "mobile_ios", "os": "iOS"},
    "D4E22F": {"vendor": "Roku Inc.", "type": "media_device", "os": "Roku OS", "model": "Roku Streaming Player"},
    "BC4486": {"vendor": "Samsung Electronics", "type": "smart_tv", "os": "Tizen", "model": "Samsung Smart TV"},
    "BC7E8B": {"vendor": "Samsung Electronics", "type": "smart_tv", "os": "Tizen", "model": "Samsung Smart TV"},
    "380195": {"vendor": "Samsung Electronics", "type": "smart_tv", "os": "Tizen", "model": "Samsung Smart TV"},
    "5C7D7D": {"vendor": "Samsung Electronics", "type": "mobile_android", "os": "Android"},
    "8C6A8D": {"vendor": "Google LLC", "type": "media_device", "os": "CastOS", "model": "Google Nest / Chromecast"},
    "9C1E95": {"vendor": "Technicolor / Vantiva", "type": "stb", "os": "Linux", "model": "IPTV Set-Top Box"},
    "244BFE": {"vendor": "Microsoft Corporation", "type": "workstation", "os": "Windows", "model": "Windows Workstation"},
    "1CCE51": {"vendor": "Lenovo", "type": "workstation", "os": "Windows", "model": "ThinkCentre / ThinkPad"},
    "1062E5": {"vendor": "Verified Host", "type": "server", "os": "Linux", "model": "Linux Server Node"},
    "AABBCC": {"vendor": "Roku Inc.", "type": "media_device", "os": "Roku OS", "model": "Roku Streaming Player"},
    "28EA0B": {"vendor": "Foxconn", "type": "workstation", "os": "Windows", "model": "Foxconn / Windows Workstation"}
}


class DeviceIdentityProfileManager:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(DeviceIdentityProfileManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, storage_path: Optional[str] = None):
        if storage_path:
            self.path = Path(storage_path)
        else:
            default_path = Path(__file__).resolve().parent.parent / "device_identity_profiles.json"
            if not default_path.exists():
                alt_path = Path(__file__).resolve().parent.parent.parent / "device_identity_profiles.json"
                if alt_path.exists():
                    default_path = alt_path
            self.path = default_path
        self.storage_path = str(self.path)
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self._load_and_migrate()

    def _clean_mac(self, mac_raw: str) -> str:
        if not mac_raw:
            return ""
        mac = mac_raw.upper().replace("MAC_", "").replace("-", ":").strip()
        parts = mac.split(":")
        if len(parts) == 6:
            try:
                return ":".join(f"{int(p, 16):02X}" for p in parts)
            except ValueError:
                return mac
        return mac

    def _lookup_oui(self, mac: str) -> Dict[str, str]:
        clean = mac.replace(":", "").replace("-", "").upper()[:6]
        if clean in IEEE_OUI_MAP:
            return IEEE_OUI_MAP[clean]
        vendor = OuiRegistry.get_instance().lookup(clean)
        if vendor:
            inferred = OuiRegistry.get_instance().infer_archetype(vendor)
            return {
                "vendor": vendor,
                "type": inferred.get("type", "unknown"),
                "model": f"{vendor} Device"
            }
        return {}

    def _load_and_migrate(self) -> None:
        with self._lock:
            if not self.path.exists():
                return

            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
            except Exception:
                raw_data = {}

            self.profiles = {}
            for k, v in raw_data.items():
                if not isinstance(v, dict):
                    continue
                mac = self._clean_mac(v.get("mac", k))
                if not mac or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                    continue

                existing = self.profiles.get(mac, {})
                merged = {**existing, **v}
                merged["mac"] = mac

                # Normalize OUI
                oui_info = self._lookup_oui(mac)
                if oui_info:
                    if merged.get("vendor") in ("Unknown", "Unknown Vendor", "Verified Host", "generic", None) or (oui_info.get("vendor") and merged.get("vendor") in ("Ubiquiti Networks", "Technicolor", "Industrial Automation", "Mercury Security")):
                        merged["vendor"] = oui_info["vendor"]
                    if merged.get("dev_type") in ("unknown", "generic", "workstation", "server", None) or oui_info.get("type") in ("smart_tv", "mobile_ios", "mobile_android", "media_device", "stb", "access_control", "plc", "switch", "workstation"):
                        merged["dev_type"] = oui_info["type"]
                        merged["type"] = oui_info["type"]
                    if merged.get("os_family") in ("unknown", "linux", "network", None) or (oui_info.get("os") and oui_info.get("os") != "Linux"):
                        if oui_info.get("os"):
                            merged["os_family"] = oui_info["os"]
                    if merged.get("model") in ("Generic Endpoint", "Network Service", "404 - Not Found", "Accueil", "Smart TV", "Smart TV / Display", None) or oui_info.get("model"):
                        if oui_info.get("model"):
                            merged["model"] = oui_info["model"]

                # Filter bad HTTP titles
                model_lower = str(merged.get("model", "")).strip().lower()
                if model_lower in BLACKLIST_TITLES:
                    merged["model"] = oui_info.get("model", "Generic Endpoint")

                # Sanitize hostname from bad titles
                host_lower = str(merged.get("hostname", "")).strip().lower()
                if host_lower in BLACKLIST_TITLES:
                    merged["hostname"] = ""

                # Progressive confidence
                has_oui = bool(merged.get("vendor") and merged["vendor"] not in ("Unknown", "Unknown Vendor", "generic", ""))
                has_os = bool(merged.get("os_family") and merged["os_family"] not in ("unknown", "linux") or (merged.get("os_family") == "linux" and oui_info.get("os") == "Linux"))
                has_model = bool(merged.get("model") and merged["model"] not in ("Generic Endpoint", "Network Service", "Generic Device", ""))
                has_host = bool(merged.get("hostname"))

                conf = 0.50 if has_oui else 0.30
                if merged.get("vendor") and merged["vendor"] not in ("Unknown", "Unknown Vendor", "generic"):
                    conf += 0.25
                if merged.get("dev_type") and merged["dev_type"] not in ("unknown", "generic"):
                    conf += 0.15
                if has_model:
                    conf += 0.08
                if has_host:
                    conf = max(conf, 0.98)
                merged["confidence"] = round(min(0.98, conf), 2)

                self.profiles[mac] = merged

            self._save()

    def _save(self) -> None:
        with self._lock:
            try:
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.profiles, f, indent=2)
            except Exception:
                pass

    def load_profiles(self) -> None:
        """Loads saved DIP profiles from disk and applies sanitization and migration."""
        self._load_and_migrate()

    def save_profiles(self) -> None:
        """Persists sanitized DIP profiles to disk safely."""
        self._save()

    def lookup(self, mac: str) -> Optional[Dict[str, Any]]:
        clean_mac = self._clean_mac(mac)
        if not clean_mac or clean_mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return None
        with self._lock:
            return self.profiles.get(clean_mac)

    lookup_by_mac = lookup

    def lookup_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Finds the most confident profile matching a given IP address, excluding broadcast/null MACs."""
        if not ip:
            return None
        with self._lock:
            candidates = []
            for mac, prof in self.profiles.items():
                if prof.get("ip") == ip and mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    candidates.append(prof)
            if candidates:
                candidates.sort(key=lambda p: p.get("confidence", 0.0), reverse=True)
                return candidates[0]
            return None

    def get_or_create(self, mac: str, ip: str = "") -> Dict[str, Any]:
        clean_mac = self._clean_mac(mac)
        if not clean_mac or clean_mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return {}

        with self._lock:
            profile = self.lookup(clean_mac)
            if not profile:
                oui_info = self._lookup_oui(clean_mac)
                vendor = oui_info.get("vendor", "Unknown")
                dev_type = oui_info.get("type", "unknown")
                os_family = oui_info.get("os", "unknown")
                model = oui_info.get("model", "Generic Endpoint")
                conf = 0.30
                if vendor != "Unknown":
                    conf += 0.25
                if dev_type != "unknown":
                    conf += 0.15
                if model != "Generic Endpoint":
                    conf += 0.08

                profile = {
                    "mac": clean_mac,
                    "ip": ip,
                    "vendor": vendor,
                    "model": model,
                    "hostname": "",
                    "dev_type": dev_type,
                    "type": dev_type,
                    "os_family": os_family,
                    "observations": 0,
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                    "confidence": 0.30
                }
                self.profiles[clean_mac] = profile
                self._save()
            return profile

    def ingest_observation(
        self,
        mac: str,
        ip: str = "",
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        hostname: Optional[str] = None,
        dev_type: Optional[str] = None,
        os_family: Optional[str] = None,
        evidence_source: str = "probe",
        **kwargs
    ) -> Dict[str, Any]:
        clean_mac = self._clean_mac(mac)
        if not clean_mac or clean_mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return {}

        with self._lock:
            rec = self.profiles.get(clean_mac, {
                "mac": clean_mac,
                "ip": ip,
                "vendor": "Unknown",
                "model": "Generic Endpoint",
                "hostname": "",
                "dev_type": "unknown",
                "type": "unknown",
                "os_family": "unknown",
                "observations": 0,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "confidence": 0.50
            })

            if ip:
                rec["ip"] = ip
            rec["last_seen"] = time.time()
            rec["observations"] = rec.get("observations", 0) + 1
            rec["times_observed"] = rec["observations"]

            oui_info = self._lookup_oui(clean_mac)
            in_vendor = vendor or kwargs.get("vendor")
            if not in_vendor and rec.get("vendor") in ("Unknown", "Unknown Vendor", "generic", None, ""):
                in_vendor = oui_info.get("vendor")
            if in_vendor and in_vendor not in ("Unknown", "Unknown Vendor", "generic", ""):
                rec["vendor"] = in_vendor

            in_dev_type = dev_type or kwargs.get("dev_type") or kwargs.get("type")
            if not in_dev_type and rec.get("dev_type") in ("unknown", "generic", None, ""):
                in_dev_type = oui_info.get("type")
            if in_dev_type and in_dev_type not in ("unknown", "generic", ""):
                rec["dev_type"] = in_dev_type
                rec["type"] = in_dev_type

            in_os = os_family or kwargs.get("os_family")
            if not in_os and rec.get("os_family") in ("unknown", None, ""):
                in_os = oui_info.get("os")
            if in_os and in_os != "unknown":
                rec["os_family"] = in_os

            raw_model = model or kwargs.get("model")
            if not raw_model and rec.get("model") in ("Generic Endpoint", "Network Service", "Generic Device", None, ""):
                raw_model = oui_info.get("model")
            if raw_model and str(raw_model).strip().lower() not in BLACKLIST_TITLES:
                rec["model"] = raw_model

            in_hostname = hostname or kwargs.get("hostname")
            if in_hostname and str(in_hostname).strip().lower() not in BLACKLIST_TITLES and not rec.get("hostname"):
                rec["hostname"] = in_hostname

            proof_sources = set(rec.get("source_proofs", []))
            if evidence_source:
                proof_sources.add(evidence_source)
            rec["source_proofs"] = sorted(list(proof_sources))

            # Composite confidence calculation
            # Evidence depth:
            # - MAC OUI only: 50%
            # - OUI + OS TTL match: 70%
            # - OUI + Open Port / Service: 85%
            # - OUI + mDNS/DHCP Hostname or Model String: 98%
            has_oui = bool(rec.get("vendor") and rec["vendor"] not in ("Unknown", "Unknown Vendor", "generic", ""))
            has_os = (bool(rec.get("os_family") and rec["os_family"] != "unknown") and any("ttl" in s.lower() or "os" in s.lower() for s in proof_sources)) or "ttl" in evidence_source.lower()
            has_service = "port" in evidence_source.lower() or "service" in evidence_source.lower() or "deep_probe" in evidence_source.lower() or any("port" in s.lower() or "service" in s.lower() or "deep_probe" in s.lower() for s in proof_sources)
            has_name_or_model = (bool(rec.get("hostname")) and any("mdns" in s.lower() or "dhcp" in s.lower() or "active" in s.lower() for s in proof_sources)) or (bool(rec.get("model") and rec["model"] not in ("Generic Endpoint", "Network Endpoint", "Generic Device", "")) and any("banner" in s.lower() or "probe" in s.lower() or "mdns" in s.lower() or "active" in s.lower() for s in proof_sources))

            if has_oui:
                conf = 0.50
                if has_os:
                    conf = 0.70
                if has_service:
                    conf = max(conf, 0.85)
                if has_name_or_model:
                    conf = max(conf, 0.98)
            else:
                conf = 0.30
                if has_name_or_model:
                    conf = 0.80
                elif has_service:
                    conf = 0.60
                elif has_os:
                    conf = 0.50

            rec["confidence"] = round(min(0.98, conf), 2)
            self.profiles[clean_mac] = rec
            self._save()
            return rec

    def _normalize_mac(self, mac: str) -> str:
        clean = self._clean_mac(mac)
        return "" if clean == "00:00:00:00:00:00" else clean

    def lookup_dip(self, ip: str, mac: str = "", hostname: str = "", env_cidr: str = "") -> Optional[Dict[str, Any]]:
        norm_mac = self._normalize_mac(mac)
        clean_hostname = hostname.strip().lower()

        with self._lock:
            # 1. MAC match
            if norm_mac and norm_mac in self.profiles:
                prof = self.profiles[norm_mac]
                if prof.get("vendor") not in ("Unknown", "Unknown Vendor", "generic"):
                    return dict(prof)

            # 2. Hostname match
            if clean_hostname:
                for prof in self.profiles.values():
                    prof_host = str(prof.get("hostname", "")).strip().lower()
                    if prof_host and prof_host == clean_hostname:
                        if not env_cidr or prof.get("environment_cidr") == env_cidr:
                            if prof.get("vendor") not in ("Unknown", "Unknown Vendor", "generic"):
                                return dict(prof)

            # 3. IP match (guarded)
            if ip and env_cidr:
                for prof in self.profiles.values():
                    if prof.get("ip") == ip and prof.get("environment_cidr") == env_cidr:
                        prof_mac = prof.get("mac", "")
                        if norm_mac and prof_mac and prof_mac != norm_mac:
                            continue
                        p_type = prof.get("dev_type") or prof.get("type", "")
                        p_model = str(prof.get("model", "")).lower()
                        if p_type in ("mobile_ios", "mobile_android", "tablet") or any(x in p_model for x in ["iphone", "ipad", "galaxy", "pixel"]):
                            continue
                        if prof.get("vendor") not in ("Unknown", "Unknown Vendor", "generic"):
                            return dict(prof)

        return None

    def learn_device(
        self,
        ip: str,
        mac: str,
        hostname: str,
        classified: Dict[str, Any],
        env_cidr: str = "",
        source_proof: str = "active_sweep"
    ) -> Optional[Dict[str, Any]]:
        clean_mac = self._normalize_mac(mac)
        if not clean_mac:
            return None

        dev_type = classified.get("type", "unknown")
        dev_vendor = classified.get("vendor", "generic")
        dev_model = classified.get("model", "")

        # Guard bad HTTP titles in model
        if str(dev_model).strip().lower() in BLACKLIST_TITLES:
            dev_model = ""

        oui_info = self._lookup_oui(clean_mac)
        if dev_vendor in ("Unknown", "Unknown Vendor", "generic", "Verified Host", None):
            dev_vendor = oui_info.get("vendor", dev_vendor)
        if dev_type in ("unknown", "generic", None):
            dev_type = oui_info.get("type", dev_type)
        if not dev_model:
            dev_model = oui_info.get("model", "Generic Endpoint")

        with self._lock:
            existing = self.profiles.get(clean_mac, {})
            if existing.get("is_locked", False):
                existing["last_seen"] = time.time()
                existing["observations"] = existing.get("observations", 1) + 1
                existing["times_observed"] = existing["observations"]
                if ip:
                    existing["ip"] = ip
                self._save()
                return existing

            observations = existing.get("observations", 0) + 1
            first_seen = existing.get("first_seen", time.time())

            proof_sources = set(existing.get("source_proofs", []))
            if source_proof:
                proof_sources.add(source_proof)

            rec = {
                "profile_id": f"MAC_{clean_mac}",
                "environment_cidr": env_cidr or existing.get("environment_cidr", "default_lan"),
                "mac": clean_mac,
                "ip": ip or existing.get("ip", ""),
                "hostname": hostname or existing.get("hostname", ""),
                "type": dev_type,
                "dev_type": dev_type,
                "vendor": dev_vendor,
                "model": dev_model,
                "os_family": classified.get("os_family") or oui_info.get("os", existing.get("os_family", "unknown")),
                "confidence": 0.85,
                "first_seen": first_seen,
                "last_seen": time.time(),
                "observations": observations,
                "times_observed": observations,
                "is_locked": False,
                "source_proofs": sorted(list(proof_sources))
            }

            conf = 0.50
            if rec["vendor"] not in ("Unknown", "Unknown Vendor", "generic"):
                conf += 0.25
            if rec["dev_type"] not in ("unknown", "generic"):
                conf += 0.15
            if rec["model"] not in ("Generic Endpoint", "Network Endpoint", "Generic Device", ""):
                conf += 0.08
            if rec["hostname"]:
                conf = max(conf, 0.98)
            rec["confidence"] = round(min(0.98, conf), 2)

            self.profiles[clean_mac] = rec
            self._save()
            return rec

    def lock_profile(self, profile_id: str, custom_type: str, custom_vendor: str, custom_model: str, uplink_ip: Optional[str] = None) -> bool:
        clean_mac = self._clean_mac(profile_id)
        with self._lock:
            if clean_mac in self.profiles:
                prof = self.profiles[clean_mac]
                prof["type"] = custom_type
                prof["dev_type"] = custom_type
                prof["vendor"] = custom_vendor
                prof["model"] = custom_model
                if uplink_ip is not None:
                    prof["uplink_ip"] = uplink_ip
                prof["is_locked"] = True
                prof["confidence"] = 1.0
                self._save()
                return True
        return False

    def get_all_profiles(self, env_cidr: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if not env_cidr:
                return list(self.profiles.values())
            return [p for p in self.profiles.values() if p.get("environment_cidr") == env_cidr]

    def lookup_by_fingerprint(
        self,
        mac: str = "",
        oui: str = "",
        deep_signature: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        norm_mac = self._normalize_mac(mac)
        clean_oui = (oui or (norm_mac.replace(":", "").replace("-", "")[:6] if norm_mac else "")).upper()
        deep_signature = deep_signature or {}

        with self._lock:
            # 1. Exact MAC match
            if norm_mac and norm_mac in self.profiles:
                prof = self.profiles[norm_mac]
                if prof.get("confidence", 0.0) >= 0.85:
                    return dict(prof)

            # 2. Deep banner/signature exact match against stored signatures
            ssh_banner = deep_signature.get("banner", "") or deep_signature.get("ssh_banner", "")
            web_title = deep_signature.get("title", "") or deep_signature.get("web_title", "")
            server_header = deep_signature.get("server", "") or deep_signature.get("web_server", "")
            rtsp_server = deep_signature.get("rtsp_server", "")

            for prof in self.profiles.values():
                stored_sig = prof.get("deep_signature", {})
                if not stored_sig and not prof.get("source_proofs"):
                    continue

                if ssh_banner and (stored_sig.get("banner") == ssh_banner or ssh_banner in str(prof.get("model", ""))):
                    return dict(prof)
                if web_title and stored_sig.get("title") == web_title:
                    return dict(prof)
                if server_header and stored_sig.get("server") == server_header:
                    return dict(prof)
                if rtsp_server and stored_sig.get("rtsp_server") == rtsp_server:
                    return dict(prof)

            # 3. OUI-level matching fallback
            if clean_oui:
                for prof in self.profiles.values():
                    prof_mac = prof.get("mac", "").replace(":", "").replace("-", "").upper()
                    if prof_mac.startswith(clean_oui) and prof.get("confidence", 0.0) >= 0.85:
                        match_copy = dict(prof)
                        if norm_mac:
                            match_copy["mac"] = norm_mac
                        return match_copy

        return None

    def record_deep_signature(
        self,
        ip: str,
        mac: str,
        deep_fingerprint: Dict[str, Any],
        archetype: str,
        env_cidr: str = ""
    ) -> Dict[str, Any]:
        clean_mac = self._normalize_mac(mac)
        vendor = deep_fingerprint.get("vendor", "")
        model = deep_fingerprint.get("model", "")
        dev_type = deep_fingerprint.get("type", "workstation")
        os_hint = deep_fingerprint.get("os_hint", "")

        # Blacklist error titles from becoming model
        if str(model).strip().lower() in BLACKLIST_TITLES:
            model = ""
        title = deep_fingerprint.get("title", "")
        if str(title).strip().lower() in BLACKLIST_TITLES:
            title = ""

        oui_info = self._lookup_oui(clean_mac)
        if not vendor:
            if oui_info.get("vendor"):
                vendor = oui_info["vendor"]
            elif "Ubuntu" in os_hint or "Debian" in os_hint or "Linux" in os_hint:
                vendor = "Canonical / Linux Foundation"
                model = f"Linux Server ({os_hint})"
                dev_type = "server"
            elif "Windows" in os_hint or "Microsoft" in str(deep_fingerprint.get("server", "")):
                vendor = "Microsoft Corporation"
                model = "Windows Host"
                dev_type = "workstation"
            elif deep_fingerprint.get("protocol") == "RTSP" or "Camera" in str(deep_fingerprint.get("title", "")):
                vendor = "Network Camera Manufacturer"
                model = title or "IP Camera"
                dev_type = "camera"
            elif deep_fingerprint.get("protocol") == "MODBUS":
                vendor = "Schneider / Rockwell"
                model = "Industrial PLC / Modbus Gateway"
                dev_type = "plc"
            else:
                vendor = "Verified Host"
                model = title or "Network Service"

        if not model and oui_info.get("model"):
            model = oui_info["model"]

        classified = {
            "type": dev_type,
            "dev_type": dev_type,
            "vendor": vendor,
            "model": model or "Generic Endpoint",
            "archetype": archetype,
            "os_family": oui_info.get("os", "Linux" if "Linux" in os_hint else "unknown")
        }

        profile = self.learn_device(
            ip=ip,
            mac=clean_mac,
            hostname="",
            classified=classified,
            env_cidr=env_cidr,
            source_proof=f"deep_probe_{deep_fingerprint.get('protocol', 'TCP').lower()}"
        )

        with self._lock:
            if clean_mac in self.profiles:
                self.profiles[clean_mac]["deep_signature"] = deep_fingerprint
                self.profiles[clean_mac]["confidence"] = 0.98
                self.profiles[clean_mac]["verified_fingerprint"] = True
                self._save()
                return self.profiles[clean_mac]

        return profile or classified
