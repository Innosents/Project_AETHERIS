"""Transport-free contracts for traffic matrix aggregation and role inference."""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Frozen Pydantic payload retaining legacy dictionary access."""

    model_config = ConfigDict(frozen=True, extra="allow")

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __contains__(self, key: str) -> bool:
        if key in self.__class__.model_fields:
            return getattr(self, key) is not None
        return key in (self.__pydantic_extra__ or {})

    def keys(self):
        return self.model_dump().keys()

    def values(self):
        return self.model_dump().values()

    def items(self):
        return self.model_dump().items()

    def __len__(self) -> int:
        return len(self.model_dump())

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            raise TypeError("Declared traffic matrix fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ConversationEdgeRecordModel(_MappingCompatibleModel):
    """Validated directional conversation edge summary."""

    source: str
    target: str
    packets: int
    bytes: int
    ports: List[int] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)
    app_protocols: List[str] = Field(default_factory=list)


class TrafficMatrixSummaryModel(_MappingCompatibleModel):
    """Validated traffic matrix summary."""

    active_flows_count: int
    tracked_hosts_count: int
    total_packets: int
    total_bytes: int
    civic_cache_size: int = 0
    spatial_flows_count: int = 0
    flagged_flows_count: int = 0


class HostRoleClassificationResult(_MappingCompatibleModel):
    """Validated host role classification result."""

    role: str
    type: str
    confidence: float


class HostStatsModel(_MappingCompatibleModel):
    """Validated per-host traffic statistics."""

    ip: Optional[str] = None
    tx_packets: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    rx_bytes: int = 0
    conns_out: int = 0
    conns_in: int = 0
    total_bytes: Optional[int] = None


@runtime_checkable
class TrafficMatrixPort(Protocol):
    """Port for concurrent traffic flow aggregation."""

    def record_flow(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
        proto: str,
        byte_count: int = 0,
        app_proto: str = "",
        domain: str = "",
        hostname: str = "",
        src_civic: Optional[Dict[str, Any]] = None,
        dst_civic: Optional[Dict[str, Any]] = None,
        latency_us: float = 0.0,
    ) -> None:
        ...

    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        ...

    def get_conversation_edges(self) -> List[Dict[str, Any]]:
        ...

    def get_summary(self) -> Dict[str, Any]:
        ...

    def stop(self) -> None:
        ...


@runtime_checkable
class TrafficRoleClassifierPort(Protocol):
    """Port for traffic-derived host role inference."""

    @staticmethod
    def infer_role(ip: str, matrix: Any) -> Dict[str, Any]:
        ...


__all__ = [
    "_MappingCompatibleModel",
    "ConversationEdgeRecordModel",
    "TrafficMatrixSummaryModel",
    "HostRoleClassificationResult",
    "HostStatsModel",
    "TrafficMatrixPort",
    "TrafficRoleClassifierPort",
]
