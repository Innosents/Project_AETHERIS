"""
Project AETHERIS - Discovery Engine Port Interface
Hexagonal Protocol defining active/passive discovery orchestration, Bayesian evidence fusion,
and recursive Kalman spatial cable distance resolution.
Strict zero-I/O boundary: Contains zero scapy, socket, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List
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


class DiscoveryEngineConfig(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    prober_lead_m: float = Field(default=2.0)
    interface: Optional[str] = Field(default=None)
    enable_tap: bool = Field(default=False)
    default_nvp: float = Field(default=0.69)
    default_asic_lat_us: float = Field(default=1.2)


class DiscoveredNodeOutcome(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    node_id: str = Field(...)
    parent_switch: str = Field(...)
    archetype: str = Field(...)
    spatial_state: Optional[Dict[str, Any]] = Field(default=None)
    global_nvp: float = Field(default=0.69)


@runtime_checkable
class DiscoveryEnginePort(Protocol):
    """Hexagonal Protocol orchestrating physical network spatial discovery."""

    def process_discovered_node(
        self,
        node_id: str,
        observed_telemetry_keys: List[str],
        rtt_samples_us: List[float],
        is_anchor: bool = False,
        known_distance_m: Optional[float] = None,
        parent_switch_id: Optional[str] = None,
        path_trunk_ids: Optional[List[str]] = None
    ) -> DiscoveredNodeOutcome:
        """Fuses Bayesian evidence and calibrates Kalman physical distance for an endpoint."""
        ...

    def register_switch_trunk(
        self,
        upstream_switch_id: str,
        downstream_switch_id: str,
        length_m: float,
        media_type: str = "COPPER_CAT6A",
        asic_latency_us: Optional[float] = None
    ) -> str:
        """Registers an inter-switch backbone riser trunk."""
        ...

    def register_switch_anchor(
        self,
        switch_id: str,
        anchor_target_id: str,
        true_distance_m: float,
        measurement_variance: float = 0.25
    ) -> None:
        """Registers a ground-truth physical distance anchor."""
        ...

