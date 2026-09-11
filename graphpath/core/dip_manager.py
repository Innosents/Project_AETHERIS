"""
Device Identity Profile (DIP) Manager
Dynamic identity caching, learning, and environmental cross-referencing engine.
Persists high-confidence device fingerprints across sweeps and environments
so familiar laptops, phones, STBs, and TVs are immediately recognized and never reset to unknown.
"""

import os
import json
import time
import threading
from typing import Dict, List, Optional, Any

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
            self.storage_path = storage_path
        else:
            pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.storage_path = os.path.join(pkg_root, "device_identity_profiles.json")

    def _sanitize_profile_entry(self, prof: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitizes and repairs conflicting or corrupted profile entries (e.g. Microsoft + Apple iPhone).
        Enforces strict cross-vendor and cross-type coherence.
        """
        if not isinstance(prof, dict):
            return prof

        p = dict(prof)
        dev_type = p.get("type", "unknown")
        vendor = p.get("vendor", "generic")
        model = str(p.get("model", "")).strip()
        hostname = str(p.get("hostname", "")).lower()

        # Check for Apple mobile model contamination on non-Apple/Windows/Infrastructure devices
        is_apple_model = any(x in model.lower() for x in ["iphone", "ipad", "apple ios"])
        is_laptop_hostname = any(token in hostname for token in ("-lp", "_lp", "lp0", "lp1", "lp2", "lp3", "lp4", "lp5", "lp6", "lp7", "lp8", "lp9", "laptop", "surface", "thinkpad", "macbook", "xps", "latitude", "elitebook", "probook"))
        is_pc_hostname = any(token in hostname for token in ("-pc", "_pc", "pc0", "pc1", "pc2", "pc3", "ws0", "ws1", "ws2", "desktop"))
        is_windows_identity = (
            vendor in ("Microsoft Corporation", "Microsoft Windows", "Microsoft")
            or "windows" in model.lower()
            or dev_type in ("workstation", "server")
            or is_laptop_hostname
            or is_pc_hostname
        )

        if is_apple_model:
            if is_windows_identity or dev_type in ("workstation", "server", "laptop"):
                if vendor == "Apple Inc." and is_laptop_hostname:
                    p["type"] = "laptop"
                    p["model"] = "Apple MacBook"
                else:
                    p["vendor"] = "Microsoft Corporation" if vendor in ("generic", "Apple Inc.", "Unknown Vendor", "Microsoft") else vendor
                    if is_laptop_hostname or dev_type == "laptop":
                        p["type"] = "laptop"
                        p["model"] = "Windows Portable Laptop"
                    elif dev_type == "server":
                        p["type"] = "server"
                        p["model"] = "Windows Server Host"
                    else:
                        p["type"] = "workstation"
                        p["model"] = "Windows Enterprise Workstation"
            elif dev_type in ("printer", "switch", "router", "firewall", "plc", "camera", "nvr"):
                p["model"] = f"Network {dev_type.capitalize()}"
            elif vendor != "Apple Inc." and vendor not in ("generic", "Unknown Vendor"):
                # Non-Apple vendor with iPhone model -> sanitize model
                p["model"] = f"{vendor} Device"

        # Sanitize AirPrint printer misclassifications
        if p.get("type") == "printer" and p.get("vendor") == "Apple Inc.":
            if "brw" in hostname or "brother" in hostname:
                p["vendor"] = "Brother"
                p["model"] = "Brother Network Printer"
            elif "hp" in hostname or "laserjet" in hostname:
                p["vendor"] = "HP Inc."
                p["model"] = "HP LaserJet Printer"
            elif "kyocera" in hostname:
                p["vendor"] = "Kyocera Document Solutions"
                p["model"] = "Kyocera MFP Printer"
            elif "canon" in hostname:
                p["vendor"] = "Canon"
                p["model"] = "Canon Network Printer"
            else:
                p["vendor"] = "Network Printer Vendor"
                p["model"] = "Multifunction Network Printer (MFP)"

        return p

    def load_profiles(self) -> None:
        """Loads saved DIP profiles from disk and applies runtime sanitization."""
        with self._lock:
            dirty = False
            if os.path.exists(self.storage_path):
                try:
                    with open(self.storage_path, "r", encoding="utf-8") as f:
                        raw_profiles = json.load(f)
                    self.profiles = {}
                    for k, v in raw_profiles.items():
                        sanitized = self._sanitize_profile_entry(v)
                        if sanitized != v:
                            dirty = True
                        self.profiles[k] = sanitized
                except Exception as e:
                    print(f"[DIP Manager] Warning: Failed to load profiles from {self.storage_path}: {e}")
                    self.profiles = {}
            else:
                self.profiles = {}
            if dirty:
                self.save_profiles()

    def save_profiles(self) -> None:
        """Persists sanitized DIP profiles to disk safely."""
        with self._lock:
            try:
                sanitized_dict = {k: self._sanitize_profile_entry(v) for k, v in self.profiles.items()}
                self.profiles = sanitized_dict
                with open(self.storage_path, "w", encoding="utf-8") as f:
                    json.dump(sanitized_dict, f, indent=4)
            except Exception as e:
                print(f"[DIP Manager] Error saving profiles to {self.storage_path}: {e}")

    def _normalize_mac(self, mac: str) -> str:
        if not mac:
            return ""
        normalized = mac.upper().replace("-", ":").strip()
        return "" if normalized == "00:00:00:00:00:00" else normalized

    def lookup_dip(self, ip: str, mac: str = "", hostname: str = "", env_cidr: str = "") -> Optional[Dict[str, Any]]:
        """
        Cross-references input attributes against stored environment profiles.
        Search Order:
        1. Exact Hardware MAC match (Highest reliability across IP changes)
        2. Hostname + Environment match (Handles randomized MACs with static hostnames)
        3. Static IP + Environment match (With DHCP lease collision protection)
        """
        norm_mac = self._normalize_mac(mac)
        clean_hostname = hostname.strip().lower()

        with self._lock:
            # 1. MAC Match (Global physical hardware anchor)
            if norm_mac:
                for key, prof in self.profiles.items():
                    if prof.get("mac") == norm_mac:
                        if prof.get("vendor") not in ("Unknown Vendor", "generic") and prof.get("type") not in ("unknown", "subnet"):
                            return self._sanitize_profile_entry(dict(prof))

            # 2. Hostname Match within Environment
            if clean_hostname:
                for key, prof in self.profiles.items():
                    prof_host = str(prof.get("hostname", "")).strip().lower()
                    if prof_host and prof_host == clean_hostname:
                        if not env_cidr or prof.get("environment_cidr") == env_cidr:
                            if prof.get("vendor") not in ("Unknown Vendor", "generic"):
                                return self._sanitize_profile_entry(dict(prof))

            # 3. IP Match within Specific Environment (Guarded against DHCP lease rotation & mobile devices)
            if ip and env_cidr:
                for key, prof in self.profiles.items():
                    if prof.get("ip") == ip and prof.get("environment_cidr") == env_cidr:
                        # Guard: If queried device has a known MAC, reject IP match if profile has a different MAC
                        prof_mac = prof.get("mac", "")
                        if norm_mac and prof_mac and prof_mac != norm_mac:
                            continue

                        # Guard: Dynamic mobile devices (iPhones, Android phones, Tablets) must never match on IP-only
                        p_type = prof.get("type", "")
                        p_model = str(prof.get("model", "")).lower()
                        if p_type in ("mobile_ios", "mobile_android", "tablet") or any(x in p_model for x in ["iphone", "ipad", "galaxy", "pixel"]):
                            continue

                        if prof.get("type") and prof.get("type") not in ("unknown", "subnet") and prof.get("vendor") not in ("Unknown Vendor", "generic"):
                            return self._sanitize_profile_entry(dict(prof))

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
        """
        Dynamically learns and saves a high-confidence device identity profile.
        Enforces strict cross-vendor sanitization before persistence.
        """
        dev_type = classified.get("type", "unknown")
        dev_vendor = classified.get("vendor", "generic")
        dev_model = classified.get("model", "")

        # Guard: Sanitize invalid Apple iPhone models on Windows workstations/servers
        is_windows = (
            dev_vendor in ("Microsoft Corporation", "Microsoft Windows")
            or classified.get("os_vendor") == "Microsoft Corporation"
            or "windows" in str(classified.get("os_version", "")).lower()
            or dev_type in ("workstation", "server")
        )
        if is_windows and any(x in str(dev_model).lower() for x in ["iphone", "ipad", "ios device"]):
            dev_vendor = "Microsoft Corporation"
            dev_model = "Windows Enterprise Workstation" if dev_type == "workstation" else "Windows Server Host"
            classified["vendor"] = dev_vendor
            classified["model"] = dev_model

        if not dev_type or dev_type in ("unknown", "subnet") or dev_vendor in ("Unknown Vendor", "generic"):
            return None

        norm_mac = self._normalize_mac(mac)
        
        # Determine unique profile key (Prefer MAC, fallback to IP_ENV)
        if norm_mac:
            profile_key = f"MAC_{norm_mac}"
        elif hostname:
            profile_key = f"HOST_{hostname.strip().upper()}_{env_cidr}"
        elif ip and env_cidr:
            profile_key = f"IP_{ip}_{env_cidr}"
        else:
            return None

        current_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        with self._lock:
            existing = self.profiles.get(profile_key, {})
            
            # If profile was locked by user, preserve user overrides
            if existing.get("is_locked", False):
                existing["last_seen"] = current_time
                existing["times_observed"] = existing.get("times_observed", 1) + 1
                existing["ip"] = ip or existing.get("ip")
                self.save_profiles()
                return existing

            times_observed = existing.get("times_observed", 0) + 1
            first_seen = existing.get("first_seen", current_time)

            # Calculate confidence score
            confidence = 0.85
            if norm_mac:
                confidence += 0.05
            if hostname:
                confidence += 0.05
            if dev_model and dev_model not in ("Network Endpoint", "Windows Host", "UPnP Device", "Generic Device"):
                confidence += 0.05
            confidence = min(1.0, confidence)

            proof_sources = set(existing.get("source_proofs", []))
            if source_proof:
                proof_sources.add(source_proof)

            vendor = dev_vendor or existing.get("vendor", "generic")
            model = dev_model or existing.get("model", "Network Endpoint")

            raw_profile = {
                "profile_id": profile_key,
                "environment_cidr": env_cidr or existing.get("environment_cidr", "default_lan"),
                "mac": norm_mac or existing.get("mac", ""),
                "ip": ip or existing.get("ip", ""),
                "hostname": hostname or existing.get("hostname", ""),
                "type": dev_type,
                "vendor": vendor,
                "model": model,
                "confidence": round(confidence, 2),
                "first_seen": first_seen,
                "last_seen": current_time,
                "times_observed": times_observed,
                "is_locked": False,
                "source_proofs": sorted(list(proof_sources))
            }

            profile = self._sanitize_profile_entry(raw_profile)
            self.profiles[profile_key] = profile

        self.save_profiles()
        return profile

    def lock_profile(self, profile_id: str, custom_type: str, custom_vendor: str, custom_model: str, uplink_ip: Optional[str] = None) -> bool:
        """Allows pinning or manually overriding a device identity profile and physical uplink."""
        with self._lock:
            if profile_id in self.profiles:
                prof = self.profiles[profile_id]
                prof["type"] = custom_type
                prof["vendor"] = custom_vendor
                prof["model"] = custom_model
                if uplink_ip is not None:
                    prof["uplink_ip"] = uplink_ip
                prof["is_locked"] = True
                prof["confidence"] = 1.0
                self.save_profiles()
                return True
        return False

    def get_all_profiles(self, env_cidr: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns all registered DIP records, optionally filtered by environment CIDR."""
        with self._lock:
            if not env_cidr:
                return list(self.profiles.values())
            return [p for p in self.profiles.values() if p.get("environment_cidr") == env_cidr]
