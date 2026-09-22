"""
Project AETHERIS - Infrastructure Probers: Input-Output Hidden Markov Model (IO-HMM) Engine
Conditioned Bayesian state estimation and online stochastic parameter learning.
Hexagonal Infrastructure Layer: Implements probers and online learners conforming to domain contracts.
"""

from abc import ABC, abstractmethod
from typing import Optional
import numpy as np

from aetheris.domain.models.topology_states import (
    EdgeState,
    ExternalProbeVector,
    DynamicHMMTensors,
    SufficientStatistics,
    IndustrialProtocol,
)
from aetheris.domain.math.bayesian_anchors import (
    DirichletPriors,
    m_step_with_dirichlet_anchors,
)


class IOHMMAdapter(ABC):
    """
    Abstract Base Class for Input-Output Hidden Markov Model condition adapters.
    Governs generation of transition and emission tensors conditioned on exogenous telemetry.
    """

    @abstractmethod
    def condition_tensors(self, vector: ExternalProbeVector) -> DynamicHMMTensors:
        pass


class HardwareStateProber(IOHMMAdapter):
    """
    Concrete prober adapter mapping physical hardware and network telemetry
    into dynamically conditioned HMM tensors.
    """

    DEFAULT_TRANSITION_BASE: np.ndarray = np.array(
        [
            [0.96, 0.03, 0.008, 0.002],
            [0.10, 0.85, 0.04,  0.01],
            [0.01, 0.04, 0.94,  0.01],
            [0.001, 0.009, 0.01, 0.98],
        ],
        dtype=np.float64,
    )

    DEFAULT_EMISSION_BASE: np.ndarray = np.array(
        [
            [0.90, 0.08, 0.018, 0.002],
            [0.08, 0.70, 0.20,  0.02],
            [0.02, 0.18, 0.75,  0.05],
            [0.001, 0.01, 0.089, 0.90],
        ],
        dtype=np.float64,
    )

    DEFAULT_INITIAL_PI: np.ndarray = np.array(
        [0.95, 0.03, 0.01, 0.01],
        dtype=np.float64,
    )

    def condition_tensors(self, vector: ExternalProbeVector) -> DynamicHMMTensors:
        transition = np.copy(self.DEFAULT_TRANSITION_BASE)

        persistence = float(vector.l2_mac_persistence)
        if persistence > 0.8:
            boost = (persistence - 0.8) * 0.15
            transition[EdgeState.STABLE, EdgeState.STABLE] += boost
            transition[EdgeState.STABLE, EdgeState.DEGRADED] = max(
                0.001, transition[EdgeState.STABLE, EdgeState.DEGRADED] - boost * 0.7
            )
            transition[EdgeState.STABLE, EdgeState.SPLICED] = max(
                0.0005, transition[EdgeState.STABLE, EdgeState.SPLICED] - boost * 0.3
            )
        else:
            deficit = (0.8 - persistence) * 0.2
            transition[EdgeState.STABLE, EdgeState.SPLICED] += deficit * 0.6
            transition[EdgeState.STABLE, EdgeState.DEGRADED] += deficit * 0.4
            transition[EdgeState.STABLE, EdgeState.STABLE] -= deficit

        if vector.uses_industrial_protocol:
            transition[EdgeState.STABLE, EdgeState.DEGRADED] *= 0.5
            transition[EdgeState.DEGRADED, EdgeState.STABLE] *= 1.2

        transition = np.maximum(transition, 1e-12)
        transition /= np.sum(transition, axis=1, keepdims=True)

        emission = np.copy(self.DEFAULT_EMISSION_BASE)
        if vector.baseline_latency_ms > 50.0:
            emission[EdgeState.STABLE, 1] += 0.05
            emission[EdgeState.STABLE, 0] -= 0.05
        elif vector.baseline_latency_ms < 1.0 and vector.uses_industrial_protocol:
            emission[EdgeState.STABLE, 0] = 0.97
            emission[EdgeState.STABLE, 1] = 0.025
            emission[EdgeState.STABLE, 2] = 0.004
            emission[EdgeState.STABLE, 3] = 0.001

        emission = np.maximum(emission, 1e-12)
        emission /= np.sum(emission, axis=1, keepdims=True)

        pi = np.copy(self.DEFAULT_INITIAL_PI)
        if persistence > 0.9:
            pi[EdgeState.STABLE] = 0.98
            pi[EdgeState.DEGRADED] = 0.015
            pi[EdgeState.SPLICED] = 0.003
            pi[EdgeState.SEVERED] = 0.002
            pi /= np.sum(pi)

        return {
            "initial_probabilities": pi.astype(np.float64),
            "transition_matrix": transition.astype(np.float64),
            "emission_matrix": emission.astype(np.float64),
        }


class OnlineIOHMMTuner(ABC):
    @abstractmethod
    def forward_step(
        self,
        observation: int,
        input_vector: ExternalProbeVector,
    ) -> np.ndarray:
        pass

    @abstractmethod
    def update_step(
        self,
        observation: int,
        input_vector: ExternalProbeVector,
        protocol: IndustrialProtocol,
    ) -> DynamicHMMTensors:
        pass


class HardwareStateLearner(OnlineIOHMMTuner):
    def __init__(
        self,
        prober: Optional[IOHMMAdapter] = None,
        gamma_0: float = 1.0,
        tau: float = 20.0,
        kappa: float = 0.7,
        initial_vector: Optional[ExternalProbeVector] = None,
    ) -> None:
        if not (0.5 < kappa <= 1.0):
            raise ValueError(f"Robbins-Monro exponent kappa must satisfy 0.5 < kappa <= 1.0, got {kappa}")
        if gamma_0 <= 0.0:
            raise ValueError(f"gamma_0 must be strictly positive, got {gamma_0}")
        if tau < 0.0:
            raise ValueError(f"tau must be non-negative, got {tau}")

        self.prober: IOHMMAdapter = prober or HardwareStateProber()
        self.gamma_0: float = float(gamma_0)
        self.tau: float = float(tau)
        self.kappa: float = float(kappa)
        self.step_count: int = 0

        seed_vector = initial_vector or ExternalProbeVector(
            hardware_profile_id=1,
            baseline_latency_ms=10.0,
            l2_mac_persistence=0.95,
            uses_industrial_protocol=False,
        )
        self.current_tensors: DynamicHMMTensors = self.prober.condition_tensors(seed_vector)
        self.alpha_t: np.ndarray = np.copy(self.current_tensors["initial_probabilities"])
        self.sufficient_stats: np.ndarray = np.copy(self.current_tensors["transition_matrix"]) * 10.0
        self.state_occupancy: np.ndarray = np.copy(self.alpha_t) * 10.0

    @property
    def learning_rate(self) -> float:
        return self.gamma_0 / ((self.step_count + self.tau) ** self.kappa)

    def forward_step(
        self,
        observation: int,
        input_vector: ExternalProbeVector,
    ) -> np.ndarray:
        conditioned = self.prober.condition_tensors(input_vector)
        A = self.current_tensors["transition_matrix"]
        B = conditioned["emission_matrix"]

        if not (0 <= observation < B.shape[1]):
            raise ValueError(f"Observation index {observation} exceeds emission dimension {B.shape[1]}")

        prior_state = np.dot(self.alpha_t, A)
        likelihood = B[:, observation]
        alpha_raw = prior_state * likelihood
        c_t = float(np.sum(alpha_raw))

        if c_t <= 1e-15:
            hat_alpha = prior_state / max(1e-15, float(np.sum(prior_state)))
        else:
            hat_alpha = alpha_raw / c_t

        self.alpha_t = hat_alpha.astype(np.float64)
        return np.copy(self.alpha_t)

    def update_step(
        self,
        observation: int,
        input_vector: ExternalProbeVector,
        protocol: IndustrialProtocol,
    ) -> DynamicHMMTensors:
        self.step_count += 1
        gamma = self.learning_rate

        prev_alpha = np.copy(self.alpha_t)
        conditioned = self.prober.condition_tensors(input_vector)
        A = self.current_tensors["transition_matrix"]
        B = conditioned["emission_matrix"]

        if not (0 <= observation < B.shape[1]):
            raise ValueError(f"Observation index {observation} exceeds emission dimension {B.shape[1]}")

        prior_state = np.dot(prev_alpha, A)
        likelihood = B[:, observation]
        alpha_raw = prior_state * likelihood
        c_t = max(float(np.sum(alpha_raw)), 1e-15)

        instantaneous_transitions = (
            np.outer(prev_alpha, likelihood) * A
        ) / c_t

        self.alpha_t = (alpha_raw / c_t).astype(np.float64)

        self.sufficient_stats = (
            (1.0 - gamma) * self.sufficient_stats + gamma * instantaneous_transitions
        ).astype(np.float64)

        updated_transition = m_step_with_dirichlet_anchors(
            self.sufficient_stats,
            protocol,
        )

        self.current_tensors = {
            "initial_probabilities": np.copy(self.current_tensors["initial_probabilities"]),
            "transition_matrix": updated_transition,
            "emission_matrix": np.copy(B),
        }

        return self.current_tensors

