"""
Project AETHERIS - Domain Math: Bayesian Anchors & Dirichlet Regularization
Pure mathematical inference functions for updating transition distributions without catastrophic forgetting.
Hexagonal Domain Layer: ZERO external infrastructure imports. Pure NumPy (np.float64) execution.
"""

from typing import Dict
import numpy as np

from aetheris.domain.models.topology_states import IndustrialProtocol


class DirichletPriors:
    """
    Immutable repository of strict Dirichlet pseudo-count matrices (alpha).
    Prevents catastrophic forgetting during online Bayesian M-step updates across OT/ICS networks.
    All matrices are strictly (4, 4) corresponding to [STABLE, DEGRADED, SPLICED, SEVERED].
    """

    PROFINET_IRT: np.ndarray = np.array(
        [
            [250.0, 2.0, 0.5, 0.1],
            [10.0, 100.0, 2.0, 1.0],
            [1.0, 5.0, 100.0, 2.0],
            [0.1, 0.5, 1.0, 250.0],
        ],
        dtype=np.float64,
    )

    MODBUS_TCP: np.ndarray = np.array(
        [
            [150.0, 10.0, 1.0, 0.5],
            [15.0, 120.0, 3.0, 2.0],
            [2.0, 8.0, 80.0, 3.0],
            [0.5, 1.0, 2.0, 150.0],
        ],
        dtype=np.float64,
    )

    ETHERNET_IP_CIP: np.ndarray = np.array(
        [
            [180.0, 8.0, 1.0, 0.5],
            [12.0, 110.0, 2.5, 1.5],
            [1.5, 6.0, 90.0, 2.5],
            [0.5, 1.0, 1.5, 200.0],
        ],
        dtype=np.float64,
    )

    GENERIC_L2: np.ndarray = np.array(
        [
            [100.0, 15.0, 2.0, 1.0],
            [20.0, 80.0, 5.0, 4.0],
            [3.0, 10.0, 60.0, 5.0],
            [1.0, 2.0, 3.0, 100.0],
        ],
        dtype=np.float64,
    )

    _REGISTRY: Dict[IndustrialProtocol, np.ndarray] = {
        IndustrialProtocol.PROFINET_IRT: PROFINET_IRT,
        IndustrialProtocol.MODBUS_TCP: MODBUS_TCP,
        IndustrialProtocol.ETHERNET_IP_CIP: ETHERNET_IP_CIP,
        IndustrialProtocol.GENERIC_L2: GENERIC_L2,
    }

    @classmethod
    def get_prior(cls, protocol: IndustrialProtocol) -> np.ndarray:
        prior = cls._REGISTRY.get(protocol, cls.GENERIC_L2)
        return np.copy(prior)


def m_step_with_dirichlet_anchors(
    sufficient_stats: np.ndarray,
    protocol: IndustrialProtocol,
) -> np.ndarray:
    """
    Executes a Maximum A Posteriori (MAP) M-Step parameter update using Dirichlet prior anchors.
    """
    if not isinstance(sufficient_stats, np.ndarray):
        sufficient_stats = np.asarray(sufficient_stats, dtype=np.float64)

    if sufficient_stats.shape != (4, 4):
        raise ValueError(
            f"sufficient_stats must possess shape (4, 4), received shape {sufficient_stats.shape}"
        )

    if np.any(sufficient_stats < 0.0):
        raise ValueError("sufficient_stats elements must be non-negative real numbers")

    alpha_prior = DirichletPriors.get_prior(protocol)
    posterior_counts = sufficient_stats.astype(np.float64) + alpha_prior
    row_sums = np.sum(posterior_counts, axis=1, keepdims=True)
    row_sums = np.maximum(row_sums, 1e-15)
    transition_matrix = posterior_counts / row_sums
    return transition_matrix.astype(np.float64)

