"""Transport-free contracts for affine-invariant spatial MCMC sampling."""

from typing import Any, List, Optional, Protocol, runtime_checkable

import numpy as np
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

    def items(self):
        return self.model_dump().items()

    def values(self):
        return self.model_dump().values()

    def __len__(self) -> int:
        return len(self.model_dump())

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            raise TypeError("Declared MCMC fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class McmcResultModel(_MappingCompatibleModel):
    """Validated MCMC posterior summary with legacy tuple and mapping access."""

    distance_m: float
    variance_m2: float
    confidence_pct: float
    acceptance_fraction: float
    t_kernel_median_us: float

    def __iter__(self):
        yield self.distance_m
        yield self.variance_m2
        yield self.confidence_pct
        yield self.acceptance_fraction
        yield self.t_kernel_median_us


@runtime_checkable
class SpatialMcmcSamplerPort(Protocol):
    """Port for affine-invariant spatial MCMC sampling."""

    def log_prior(self, theta: np.ndarray, archetype: str, oui: str = "") -> float:
        ...

    def log_likelihood(self, theta: np.ndarray, rtt_samples_s: np.ndarray) -> float:
        ...

    def log_posterior(
        self,
        theta: np.ndarray,
        rtt_samples_s: np.ndarray,
        archetype: str,
        oui: str = "",
    ) -> float:
        ...

    def sample(
        self,
        rtt_samples_us: List[float],
        archetype: str = "GENERIC_HOST",
        oui: str = "",
        riser_overhead_us: float = 0.0,
    ) -> McmcResultModel:
        ...

    def sample_from_redis(
        self,
        mac: str,
        archetype: str = "GENERIC_HOST",
        oui: str = "",
        riser_overhead_us: float = 0.0,
        ledger: Optional[Any] = None,
    ) -> McmcResultModel:
        ...


__all__ = ["McmcResultModel", "SpatialMcmcSamplerPort"]