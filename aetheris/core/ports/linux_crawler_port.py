"""
Project AETHERIS - Linux SSH Endpoint Crawler Port
Hexagonal Protocol defining remote SSH Linux endpoint telemetry extraction,
distribution / kernel profiling, memory topology analysis, listening port dissection,
and broadcast domain ARP cache crawling.
Strict zero-I/O boundary: Contains zero paramiko, socket, subprocess, or sqlite3 imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Union
from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(dict):
    """Dual-mode structure supporting attribute lookups, dict access, CPython json.dumps, and frozen immutability."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        is_frozen = getattr(self.__class__, "_frozen", False) or getattr(self.__class__, "frozen", False)
        if hasattr(self.__class__, "model_config"):
            cfg = getattr(self.__class__, "model_config")
            if isinstance(cfg, dict) and cfg.get("frozen"):
                is_frozen = True
            elif getattr(cfg, "frozen", False):
                is_frozen = True
        if hasattr(self.__class__, "Config"):
            cfg_cls = getattr(self.__class__, "Config")
            if getattr(cfg_cls, "frozen", False):
                is_frozen = True
        object.__setattr__(self, "_is_frozen", is_frozen)

    def __getattribute__(self, item: str) -> Any:
        try:
            return self[item]
        except (KeyError, TypeError):
            pass
        return super().__getattribute__(item)

    def __setattr__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        self[item] = value

    def __setitem__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__setitem__(item, value)

    def __delattr__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        try:
            del self[item]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{item}'")

    def __delitem__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__delitem__(item)

    def get(self, item: str, default: Any = None) -> Any:
        return super().get(item, default)

    def model_dump(self) -> Dict[str, Any]:
        return dict(self)

    def dict(self) -> Dict[str, Any]:
        return dict(self)


class LinuxArpNeighbor(_MappingCompatibleModel):
    """Immutable record for a Layer-2/3 neighbor discovered in Linux kernel ARP cache."""
    model_config = ConfigDict(frozen=True)
    ip: str = Field(...)
    mac: str = Field(...)
    interface: Optional[str] = Field(default=None)


class LinuxHostTelemetry(_MappingCompatibleModel):
    """Immutable telemetry model capturing remote Linux system attributes."""
    model_config = ConfigDict(frozen=True, extra="allow")
    ip: str = Field(...)
    type: str = Field(default="server")
    os: str = Field(default="Linux")
    os_version: str = Field(default="Linux")
    total_ram_mb: Optional[str] = Field(default=None)
    running_services: Optional[str] = Field(default=None)
    arp_neighbors: List[LinuxArpNeighbor] = Field(default_factory=list)
    discovery_method: str = Field(default="tier_2_linux_ssh")


class LinuxCrawlerRunSummary(_MappingCompatibleModel):
    """Immutable aggregation summary for batch Linux SSH crawler sweeps."""
    model_config = ConfigDict(frozen=True)
    total_targets: int = Field(default=0)
    successful_crawls: int = Field(default=0)
    failed_crawls: int = Field(default=0)
    discovered_hosts: List[LinuxHostTelemetry] = Field(default_factory=list)


@runtime_checkable
class LinuxCrawlerPort(Protocol):
    """Hexagonal Protocol defining Linux SSH endpoint discovery and kernel parsing."""

    @staticmethod
    def parse_os_release(raw_output: str) -> str:
        """Extracts distribution name or kernel release string."""
        ...

    @staticmethod
    def parse_mem_info(raw_output: str) -> Optional[str]:
        """Extracts total system RAM in megabytes from free/meminfo output."""
        ...

    @staticmethod
    def parse_listening_services(raw_output: str) -> Optional[str]:
        """Extracts listening network services from ss/netstat output."""
        ...

    @staticmethod
    def parse_arp_cache(raw_output: str) -> List[LinuxArpNeighbor]:
        """Extracts neighboring IP-to-MAC associations from kernel ARP table."""
        ...

    def crawl_linux_server(self, ip: str, credentials: Dict[str, str]) -> Optional[LinuxHostTelemetry]:
        """Authenticates over SSH and profiles the remote Linux endpoint."""
        ...
