"""
Project AETHERIS - Raw Packet Sniffer & Hardware Timestamp Tap Port Interface
Hexagonal Protocol defining driver loop overhead calibration, nanosecond-precision RTT pulses,
and promiscuous Layer 2/3 packet sniffing abstractions.
Strict zero-I/O boundary: Contains zero scapy, socket, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Callable
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


class DriverCalibrationSummary(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    driver_overhead_us: float = Field(default=0.0)
    iterations: int = Field(default=5)
    baseline_locked: bool = Field(default=True)


class PulseBurstResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    target_ip: str = Field(...)
    target_port: int = Field(...)
    target_mac: Optional[str] = Field(default=None)
    source_port: int = Field(default=49152)
    burst_count: int = Field(default=5)
    samples: List[float] = Field(default_factory=list)
    min_rtt_us: Optional[float] = Field(default=None)
    median_rtt_us: Optional[float] = Field(default=None)


@runtime_checkable
class RawPacketTapPort(Protocol):
    """Hexagonal Protocol defining raw packet sniffing and RTT pulse bursts."""

    def calibrate_driver_overhead(self, iterations: int = 5) -> float:
        """Measures baseline OS execution overhead to subtract dispatch latency."""
        ...

    def execute_rtt_pulse_burst(
        self,
        target_ip: str,
        target_port: int,
        target_mac: Optional[str] = None,
        source_port: int = 49152,
        burst_count: int = 5,
        inter_packet_gap_s: float = 0.005,
        timeout_s: float = 0.4
    ) -> List[float]:
        """Transmits high-precision timing pulses and returns net RTT samples in microseconds."""
        ...

    def start_listener(self, bpf_filter: str = "tcp or udp or icmp") -> None:
        """Initializes packet capture listener loop."""
        ...

    def stop_listener(self) -> None:
        """Tears down packet capture listener loop."""
        ...

