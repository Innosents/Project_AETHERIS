"""
Aetheris Unified Configuration Manager.
Parses environment profiles, credentials, and scan parameters cleanly.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional


class ConfigurationManager:
    """Manages scan boundaries, environment profiles, and target switch definitions."""

    def __init__(self, profile_name: Optional[str] = None):
        self.profile_name = profile_name or os.environ.get("AETHERIS_PROFILE")
        self.config_dir = Path(__file__).resolve().parent
        self.profile_file = self.config_dir / "environment_profiles.json"
        
        self.profiles: Dict[str, Any] = {}
        self.active_profile: Dict[str, Any] = {}
        
        self._load_profiles()
        self._resolve_active_profile()

    def _load_profiles(self) -> None:
        if self.profile_file.exists():
            try:
                with open(self.profile_file, "r", encoding="utf-8") as f:
                    self.profiles = json.load(f)
            except Exception as e:
                print(f"[Config Error] Failed to load profiles from {self.profile_file}: {e}")

    def _resolve_active_profile(self) -> None:
        if self.profile_name and self.profile_name in self.profiles:
            self.active_profile = self.profiles[self.profile_name]
        elif self.profiles:
            # Match against system subnet or fallback to the first defined profile
            default_key = next(iter(self.profiles))
            self.active_profile = self.profiles[default_key]
        else:
            # Minimal standalone fallback if no profile configuration exists
            self.active_profile = {
                "name": "Default_Fallback",
                "target_subnets": ["127.0.0.1/32"],
                "core_switches": [],
                "passive_sniff_duration": 2.0,
                "ssh": {"username": "admin", "password": ""},
                "snmp": {"community": "public"},
                "vlans_to_scan": {}
            }

    @property
    def target_subnets(self) -> List[str]:
        env_subnets = os.environ.get("AETHERIS_TARGET_SUBNETS")
        if env_subnets:
            return [s.strip() for s in env_subnets.split(",") if s.strip()]
        return self.active_profile.get("target_subnets", ["127.0.0.1/32"])

    @property
    def core_switches(self) -> List[str]:
        return self.active_profile.get("core_switches", [])

    @property
    def passive_sniff_duration(self) -> float:
        return float(self.active_profile.get("passive_sniff_duration", 5.0))

    @property
    def vlans_to_scan(self) -> Dict[str, str]:
        return self.active_profile.get("vlans_to_scan", {})

    @property
    def linux_servers(self) -> List[str]:
        return self.active_profile.get("linux_servers", [])

    def get_ssh_credentials(self) -> Dict[str, str]:
        creds = dict(self.active_profile.get("ssh", {"username": "admin", "password": ""}))
        if os.environ.get("AETHERIS_SSH_USER"):
            creds["username"] = os.environ["AETHERIS_SSH_USER"]
        if os.environ.get("AETHERIS_SSH_PASS"):
            creds["password"] = os.environ["AETHERIS_SSH_PASS"]
        return creds

    def get_linux_ssh_credentials(self) -> Dict[str, str]:
        creds = dict(self.active_profile.get("linux_ssh", self.get_ssh_credentials()))
        if os.environ.get("AETHERIS_LINUX_SSH_USER"):
            creds["username"] = os.environ["AETHERIS_LINUX_SSH_USER"]
        if os.environ.get("AETHERIS_LINUX_SSH_PASS"):
            creds["password"] = os.environ["AETHERIS_LINUX_SSH_PASS"]
        return creds

    def get_snmp_community(self) -> str:
        return os.environ.get("AETHERIS_SNMP_COMMUNITY") or self.active_profile.get("snmp", {}).get("community", "public")