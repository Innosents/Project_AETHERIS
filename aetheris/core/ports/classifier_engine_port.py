"""
Project AETHERIS - Device Classifier Engine Port.
Defines immutable Pydantic contracts and abstract protocol for multi-tier
network classification (Kullback-Leibler, Markov chains, FFT spectral decomposition).
"""

from typing import Any, Dict, List, Optional, Protocol, Tuple, Union, runtime_checkable
from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Frozen Pydantic model with legacy dictionary read surface."""

    model_config = ConfigDict(frozen=True, extra="allow")

    def __getitem__(self, key: str) -> Any:
        if key in self.__class__.model_fields:
            val = getattr(self, key)
            if val is not None:
                return val
            return val
        extra = self.__pydantic_extra__ or {}
        if key in extra:
            return extra[key]
        raise KeyError(key)

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


class DeviceObservationPayload(_MappingCompatibleModel):
    """Immutable inbound observation payload for telemetry channel ingestion."""

    channel_key: Tuple[str, str] = Field(..., description="Communication channel identifier (src, dst)")
    timestamp: float = Field(..., description="Monotonic arrival timestamp in seconds")
    size: int = Field(..., ge=0, description="Packet frame size in octets")
    op_code: str = Field(..., min_length=1, description="Protocol operation code or state token")


class HeuristicScore(_MappingCompatibleModel):
    """Scored evaluation of an individual archetype hypothesis."""

    archetype: str = Field(..., min_length=1, description="Target archetype identifier")
    score: float = Field(..., description="Log-likelihood or fused heuristic score")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Normalized probability weight")
    kl_divergence: Optional[float] = Field(default=None, ge=0.0, description="Kullback-Leibler divergence D_KL(P||Q)")
    markov_likelihood: Optional[float] = Field(default=None, description="Normalized Markov transition log-likelihood")
    spectral_delta: Optional[float] = Field(default=None, description="Frequency deviation from expected tick Hz")


class ClassifierEngineResult(_MappingCompatibleModel):
    """Fused classification outcome across target profiles."""

    channel: Tuple[str, str] = Field(..., description="Evaluated communication channel")
    posterior: Dict[str, float] = Field(default_factory=dict, description="Normalized Bayesian posterior simplex")
    dominant_archetype: Optional[str] = Field(default=None, description="Maximum a posteriori (MAP) archetype")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence of the MAP archetype")
    dominant_frequency_hz: Optional[float] = Field(default=None, ge=0.0, description="Extracted spectral tick frequency")
    power_ratio: Optional[float] = Field(default=None, ge=0.0, description="Peak-to-noise spectral power ratio")
    jitter_metrics: Optional[Dict[str, float]] = Field(default=None, description="Empirical RTT jitter deconvolution metrics")


@runtime_checkable
class DeviceClassifierEnginePort(Protocol):
    """Port contract for multi-signal network classification engines."""

    def compute_kl_divergence(
        self,
        sample_sizes: List[int],
        target_distribution: Any,
        num_bins: int = 8,
        bin_range: Tuple[int, int] = (0, 1500),
    ) -> float:
        """Calculates Kullback-Leibler divergence with Laplace smoothing."""
        ...

    def compute_markov_likelihood(
        self,
        observed_seq: List[str],
        transition_matrix: Dict[str, Dict[str, float]],
        min_seq_len: int = 2,
    ) -> float:
        """Calculates normalized DTMC log-likelihood for protocol state transitions."""
        ...

    def extract_spectral_heartbeat(
        self,
        iat_series: List[float],
        sampling_rate: Optional[float] = None,
    ) -> Tuple[float, float]:
        """Extracts dominant tick frequency and power ratio from IAT series via FFT."""
        ...

    def ingest_telemetry_event(
        self,
        channel_key: Union[Tuple[str, str], DeviceObservationPayload],
        timestamp: Optional[float] = None,
        size: Optional[int] = None,
        op_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Buffers telemetry observation and updates channel feature counters."""
        ...

    def update_channel_posterior(
        self,
        channel_key: Tuple[str, str],
    ) -> Dict[str, float]:
        """Fuses multi-signal metrics into normalized Bayesian posterior simplex."""
        ...

