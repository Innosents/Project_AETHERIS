"""Core contracts for legacy AETHERIS probes."""

import abc
from typing import Any, Dict, Optional


class BaseAetherisProbe(abc.ABC):
    """Abstract lifecycle contract shared by legacy-compatible probes."""

    def __init__(self, target_ip: str, telemetry_context: Optional[Dict[str, Any]] = None) -> None:
        self.target_ip = target_ip
        self.telemetry_context = telemetry_context or {}

    async def __aenter__(self) -> "BaseAetherisProbe":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        await self.rollback()
        return False

    @abc.abstractmethod
    async def execute(self) -> Dict[str, Any]:
        """Execute the probe lifecycle."""
        raise NotImplementedError

    @abc.abstractmethod
    async def rollback(self) -> bool:
        """Release probe state and resources."""
        raise NotImplementedError


class AetherisProbeRegistry:
    """Registry state contract retained for legacy prober imports."""

    def __init__(self) -> None:
        self.active_matrix: Dict[str, Any] = {}
        self._active_matrix = self.active_matrix
