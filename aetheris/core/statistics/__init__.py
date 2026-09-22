"""
Project AETHERIS - Core Statistics & Mathematical Utilities
Provides robust estimators, Bayesian conjugate priors, and anomaly filtration.
"""

from aetheris.core.statistics.anomaly_math import (
    robust_z_score,
    normalize_stp_path_cost,
    TelemetryAnomalyFilter,
    BayesianTurnaround,
)

__all__ = [
    "robust_z_score",
    "normalize_stp_path_cost",
    "TelemetryAnomalyFilter",
    "BayesianTurnaround",
]

