"""
Project AETHERIS - Domain Models: Topology States & Tensor Typing
Strictly isolated mathematical schemas for L1/L2 spatial inference and IO-HMM tracking.
Hexagonal Domain Layer: Zero infrastructure or active probing dependencies.
"""

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import TypedDict
import numpy as np


class EdgeState(IntEnum):
    """
    Cryptographic and physical link propagation state.
    Discrete states for hidden Markov inference across physical topologies:
    0 = STABLE: Nominal impedance, negligible jitter, calibrated propagation flight time.
    1 = DEGRADED: Conductor oxidation, high CRC/FCS error rate, buffer-bloat latency variance.
    2 = SPLICED: Inline physical parasitic tap, capacitive load, or MITM interception.
    3 = SEVERED: Open circuit, infinite attenuation, complete link discontinuity.
    """
    STABLE = 0
    DEGRADED = 1
    SPLICED = 2
    SEVERED = 3


class IndustrialProtocol(str, Enum):
    """
    Supported OT/ICS industrial communication protocols.
    Governs Dirichlet prior parameter selection to prevent catastrophic forgetting.
    """
    MODBUS_TCP = "MODBUS_TCP"
    PROFINET_IRT = "PROFINET_IRT"
    ETHERNET_IP_CIP = "ETHERNET_IP_CIP"
    GENERIC_L2 = "GENERIC_L2"


@dataclass(frozen=True)
class ExternalProbeVector:
    """
    Immutable exogenous covariate vector (u_t) conditioning the Input-Output HMM.
    Captures telemetry context to dynamically modulate transition and emission matrices.
    """
    hardware_profile_id: int
    baseline_latency_ms: float
    l2_mac_persistence: float
    uses_industrial_protocol: bool

    def __post_init__(self) -> None:
        if not (0.0 <= self.l2_mac_persistence <= 1.0):
            raise ValueError(
                f"l2_mac_persistence must be bounded within [0.0, 1.0], got {self.l2_mac_persistence}"
            )
        if self.baseline_latency_ms < 0.0:
            raise ValueError(
                f"baseline_latency_ms cannot be negative, got {self.baseline_latency_ms}"
            )


class DynamicHMMTensors(TypedDict):
    """
    Conditioned tensors for IO-HMM state propagation and likelihood evaluation.
    All tensor buffers must strictly use 64-bit float precision (np.float64).
    """
    initial_probabilities: np.ndarray  # Shape: (4,)
    transition_matrix: np.ndarray      # Shape: (4, 4), row-stochastic
    emission_matrix: np.ndarray        # Shape: (4, M), row-stochastic


class SufficientStatistics(TypedDict):
    """
    Accumulated expected sufficient statistics for online Robbins-Monro parameter updates.
    Maps transition event expectations and emission occurrences in np.float64 space.
    """
    transition_counts: np.ndarray      # Shape: (4, 4)
    state_occupancy: np.ndarray        # Shape: (4,)
    emission_counts: np.ndarray        # Shape: (4, M)

