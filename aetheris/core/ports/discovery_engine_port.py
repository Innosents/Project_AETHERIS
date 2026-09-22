"""
Project AETHERIS - Discovery Engine Hexagonal Port Contracts.
Defines immutable/mapping-compatible Pydantic models and Protocol boundaries
for active network sweeps, port interrogation, banner grabbing, and device fingerprinting.
"""

from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable
from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Pydantic model providing transparent dictionary read/write surface."""

    model_config = ConfigDict(extra="allow")

    def __getitem__(self, key: str) -> Any:
        if key in self.__class__.model_fields:
            return getattr(self, key)
        extra = self.__pydantic_extra__ or {}
        if key in extra:
            return extra[key]
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            setattr(self, key, value)
        else:
            extra = dict(self.__pydantic_extra__ or {})
            extra[key] = value
            object.__setattr__(self, "__pydantic_extra__", extra)

    def get(self, key: str, default: Any = None) -> Any:
        if key in self:
            return self[key]
        return default

    def __contains__(self, key: str) -> bool:
        if key in self.__class__.model_fields:
            return getattr(self, key) is not None
        extra = self.__pydantic_extra__ or {}
        return key in extra

    def keys(self):
        return self.model_dump().keys()

    def items(self):
        return self.model_dump().items()

    def values(self):
        return self.model_dump().values()


class DiscoverySweepConfig(_MappingCompatibleModel):
    """Configuration options governing an active discovery sweep."""

    network_cidr: str = Field(default="192.168.1.0/24", description="Target IPv4 CIDR block")
    ports: Optional[List[int]] = Field(default=None, description="Optional target TCP ports to inspect")
    timeout: float = Field(default=2.0, ge=0.1, description="Sweep timeout in seconds")
    max_workers: int = Field(default=3, ge=1, description="Concurrent sweep worker thread pool size")


class DiscoveredDeviceNode(_MappingCompatibleModel):
    """Normalized payload representing a discovered physical or virtual host."""

    ip: str = Field(..., description="IPv4 or IPv6 address")
    mac: str = Field(default="", description="Hardware MAC address")
    hostname: str = Field(default="", description="Resolved host identifier")
    vendor: str = Field(default="Unknown", description="Hardware vendor name")
    type: str = Field(default="unknown", description="Categorized device archetype")
    model: str = Field(default="Generic Endpoint", description="Specific hardware model string")
    open_ports: List[int] = Field(default_factory=list, description="Verified open TCP ports")
    banners: Dict[int, str] = Field(default_factory=dict, description="Captured L7 service banners by port")
    services: List[str] = Field(default_factory=list, description="Identified application service names")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Inferred classification confidence")


class PortScanSummary(_MappingCompatibleModel):
    """Summary of port interrogation on a single target IP."""

    ip: str = Field(..., description="Scanned target IP address")
    open_ports: List[int] = Field(default_factory=list, description="List of responsive open ports")
    scan_status: str = Field(default="COMPLETED", description="Status token: COMPLETED, TIMEOUT, or FILTERED")
    banners: Dict[int, str] = Field(default_factory=dict, description="Associated port service banners")


class DiscoveryRunSummary(_MappingCompatibleModel):
    """Telemetry report produced upon completion of a discovery sweep."""

    network_cidr: str = Field(..., description="Target network CIDR block that was swept")
    total_scanned: int = Field(default=0, ge=0, description="Total number of evaluated host IPs")
    active_hosts: int = Field(default=0, ge=0, description="Number of responding reachable hosts")
    nodes_registered: int = Field(default=0, ge=0, description="Number of nodes committed to topology graph")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Elapsed execution time in seconds")


@runtime_checkable
class NetworkScannerPort(Protocol):
    """Outbound port abstracting active ping sweeps, ARP probes, port interrogation, and banners."""

    def icmp_sweep(self, target_ips: List[str]) -> List[str]:
        """Performs ICMP echo sweep across candidate IPs, returning reachable hosts."""
        ...

    def arp_scan(self, network_cidr: str) -> List[Dict[str, str]]:
        """Executes Layer 2 ARP resolution mapping IP addresses to MACs."""
        ...

    def scan_ports(self, ip: str, ports: Optional[List[int]] = None) -> Tuple[List[int], str]:
        """Probes TCP ports on target host, returning list of open ports and status."""
        ...

    def grab_banner(self, ip: str, port: int, timeout: float = 1.0) -> str:
        """Retrieves raw service banner from open port."""
        ...

    def fingerprint_device(
        self,
        ip: str,
        mac: str,
        open_ports: List[int],
        banners: Dict[int, str],
        services: List[str],
    ) -> Dict[str, Any]:
        """Synthesizes device DNA dictionary from multi-signal observation."""
        ...

    def get_common_ports(self) -> List[int]:
        """Returns baseline list of default discovery ports."""
        ...


@runtime_checkable
class DiscoveryEnginePort(Protocol):
    """Inbound domain port orchestrating active/passive sweeps and graph topology ingestion."""

    def register_discovered_node(self, node_ip: str, telemetry: Dict[str, Any]) -> None:
        """Safely mutates topology graph within a transactional boundary."""
        ...

    def run_basic_sweep(
        self,
        network_cidr: str = "192.168.1.0/24",
        ports: Optional[List[int]] = None,
    ) -> Optional[DiscoveryRunSummary]:
        """Executes active network matrix sweep, device fingerprinting, and registration."""
        ...

    def run_passive(self, execution_timeout: float = 2.0) -> None:
        """Executes passive traffic sniffing and L2 frame interception."""
        ...

    def run_credentialed(self) -> None:
        """Executes authenticated management crawling."""
        ...

    def run_adaptive(self) -> None:
        """Executes adaptive discovery sweep adjustments."""
        ...

