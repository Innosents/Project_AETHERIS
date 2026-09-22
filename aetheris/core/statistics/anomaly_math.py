"""
Project AETHERIS - Online Anomaly Layer, Normalization & Bayesian Conjugate Turnaround
Provides:
1. Robust Z-score scaling using Median Absolute Deviation (MAD) for transit times and turnarounds
2. Logarithmic compression for Spanning Tree path costs
3. Multivariate Mahalanobis anomaly filter (TelemetryAnomalyFilter) with chi-squared boundary and Kalman variance weighting
4. Conjugate normal-normal Bayesian turnaround updater (BayesianTurnaround)
"""

import math
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import numpy as np


def robust_z_score(val: float, baseline_samples: Sequence[float], epsilon: float = 1e-9) -> float:
    """
    Computes modified Z-score using Median Absolute Deviation (MAD):
    MAD = median(|X - median(X)|)
    z = 0.6745 * (val - median(X)) / max(MAD, epsilon)

    Guarantees numerical stability and returns 0.0 on degenerate or empty distributions.
    """
    if not baseline_samples or len(baseline_samples) == 0:
        return 0.0
    arr = np.asarray(baseline_samples, dtype=np.float64)
    # Filter out NaNs/Infs
    valid_arr = arr[np.isfinite(arr)]
    if len(valid_arr) == 0:
        return 0.0

    med = float(np.median(valid_arr))
    abs_dev = np.abs(valid_arr - med)
    mad = float(np.median(abs_dev))

    if mad < epsilon:
        std = float(np.std(valid_arr))
        if std < epsilon:
            return 0.0
        return float(0.6745 * (float(val) - med) / max(std, epsilon))

    return float(0.6745 * (float(val) - med) / max(mad, epsilon))


def normalize_stp_path_cost(cost: Union[int, float], max_cost: int = 200_000_000) -> float:
    """
    Applies logarithmic compression to Spanning Tree path costs:
    cost_norm = ln(1 + min(cost, max_cost)) / ln(1 + max_cost)
    Yields normalized [0.0, 1.0] topological metric.
    """
    c = max(0.0, float(cost))
    m = max(1.0, float(max_cost))
    clamped = min(c, m)
    denom = math.log(1.0 + m)
    if denom <= 0.0:
        return 0.0
    return float(math.log(1.0 + clamped) / denom)


class TelemetryAnomalyFilter:
    """
    Online multivariate anomaly filter tracking state vector x = [t_kernel, jitter]^T.
    Evaluates squared Mahalanobis distance D^2 against chi-squared threshold at alpha=0.01 (df=2).
    Modulates Kalman measurement covariance R by anomaly weight scalar w = exp(-0.5 * D^2).
    """

    # Chi-squared cutoff for df=2, alpha=0.01: -2 * ln(0.01) ~= 9.21034037
    CHI2_ALPHA_001_DF2: float = -2.0 * math.log(0.01)

    def __init__(
        self,
        initial_mean: Optional[Sequence[float]] = None,
        initial_cov: Optional[Sequence[Sequence[float]]] = None,
        alpha: float = 0.05,
        regularization: float = 1e-6,
    ) -> None:
        self.mu = np.array(
            initial_mean if initial_mean is not None else [35.0, 5.0], dtype=np.float64
        )
        self.cov = np.array(
            initial_cov if initial_cov is not None else [[225.0, 0.0], [0.0, 25.0]],
            dtype=np.float64,
        )
        self.n_samples: int = 0
        self.alpha = float(alpha)
        self.regularization = float(regularization)

    def evaluate(self, t_kernel: float, jitter: float) -> Tuple[bool, float, float]:
        """
        Evaluates input vector against current distribution.
        Returns:
            is_valid (bool): True if D^2 <= chi2 threshold, False if rejected anomaly.
            d2 (float): Squared Mahalanobis distance.
            weight (float): Anomaly scalar weight in (0.0, 1.0].
        """
        # Guard non-finite inputs
        if not math.isfinite(t_kernel) or not math.isfinite(jitter):
            return False, float("inf"), 0.0

        x = np.array([float(t_kernel), float(jitter)], dtype=np.float64)
        diff = x - self.mu

        # Regularize covariance to guarantee positive definiteness
        cov_reg = self.cov + np.eye(2, dtype=np.float64) * self.regularization
        try:
            inv_cov = np.linalg.inv(cov_reg)
            d2 = float(diff.T @ inv_cov @ diff)
        except np.linalg.LinAlgError:
            # Fallback to diagonal variance inversion
            diag_inv = 1.0 / np.maximum(np.diag(cov_reg), self.regularization)
            d2 = float(np.sum((diff ** 2) * diag_inv))

        d2 = max(0.0, float(d2)) if math.isfinite(d2) else float("inf")
        is_valid = d2 <= self.CHI2_ALPHA_001_DF2
        # Clamped exponent to avoid underflow
        weight = float(math.exp(-0.5 * min(d2, 100.0))) if math.isfinite(d2) else 0.0

        return is_valid, d2, weight

    def update(self, t_kernel: float, jitter: float) -> None:
        """Online adaptive update of mean vector and covariance matrix."""
        if not math.isfinite(t_kernel) or not math.isfinite(jitter):
            return

        x = np.array([float(t_kernel), float(jitter)], dtype=np.float64)
        self.n_samples += 1

        if self.n_samples == 1:
            self.mu = x.copy()
            return

        diff = x - self.mu
        # Exponential moving average / adaptive learning update
        lr = self.alpha if self.n_samples > 20 else (1.0 / self.n_samples)
        self.mu = self.mu + lr * diff
        new_diff = x - self.mu
        outer_prod = np.outer(diff, new_diff)
        self.cov = (1.0 - lr) * self.cov + lr * outer_prod
        # Enforce symmetry
        self.cov = 0.5 * (self.cov + self.cov.T)

    def modulate_variance(
        self, r_base: Union[float, np.ndarray], weight: float, min_weight: float = 1e-4
    ) -> Union[float, np.ndarray]:
        """Modulates Kalman measurement variance R by anomaly weight scalar."""
        eff_weight = max(float(weight), min_weight)
        if isinstance(r_base, np.ndarray):
            return r_base / eff_weight
        return float(r_base) / eff_weight

    def get_state(self) -> Dict[str, Any]:
        return {
            "mean": [float(v) for v in self.mu],
            "covariance": [[float(x) for x in row] for row in self.cov],
            "n_samples": self.n_samples,
            "chi2_threshold": self.CHI2_ALPHA_001_DF2,
        }

    @property
    def mean(self) -> np.ndarray:
        return self.mu

    @property
    def covariance(self) -> np.ndarray:
        return self.cov

    def filter_measurement(
        self, t_kernel: float, jitter: float
    ) -> Tuple[bool, float, float]:
        """Convenience method that evaluates and updates the filter if valid."""
        is_valid, d2, weight = self.evaluate(t_kernel, jitter)
        if is_valid:
            self.update(t_kernel, jitter)
        return is_valid, d2, weight

    def reset(self) -> None:
        self.mu = np.array([35.0, 5.0], dtype=np.float64)
        self.cov = np.array([[225.0, 0.0], [0.0, 25.0]], dtype=np.float64)
        self.n_samples = 0


class BayesianTurnaround(float):
    """
    Conjugate Bayesian Gaussian estimator for kernel turnaround latencies.
    Subclasses float for zero-friction arithmetic compatibility with existing spatial models.
    Exposes dict interface ['samples'], ['mean'], ['variance'], ['prior_mean'], ['prior_var'].
    """

    def __new__(
        cls,
        mean: float,
        variance: float,
        samples: Optional[Sequence[float]] = None,
        prior_mean: Optional[float] = None,
        prior_var: Optional[float] = None,
    ):
        m = float(mean) if math.isfinite(mean) else 35.0
        instance = super().__new__(cls, m)
        instance._mean = m
        v = float(variance) if math.isfinite(variance) and variance > 0 else 25.0
        instance._variance = v
        instance._samples = (
            [float(s) for s in samples if math.isfinite(s)] if samples is not None else []
        )
        pm = float(prior_mean) if prior_mean is not None and math.isfinite(prior_mean) else m
        instance._prior_mean = pm
        pv = float(prior_var) if prior_var is not None and math.isfinite(prior_var) and prior_var > 0 else v
        instance._prior_var = pv
        return instance

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def variance(self) -> float:
        return self._variance

    @property
    def samples(self) -> List[float]:
        return self._samples

    @property
    def prior_mean(self) -> float:
        return self._prior_mean

    @property
    def prior_var(self) -> float:
        return self._prior_var

    @property
    def posterior_var(self) -> float:
        return self._variance

    def __getitem__(self, key: str) -> Any:
        if key == "mean":
            return self._mean
        if key in ("var", "variance", "posterior_var"):
            return self._variance
        if key == "samples":
            return self._samples
        if key in ("prior_mean", "prior_mu"):
            return self._prior_mean
        if key in ("prior_var", "prior_variance"):
            return self._prior_var
        raise KeyError(key)

    def update_with_observations(
        self, observations: Sequence[float], measurement_std: float = 10.0
    ) -> "BayesianTurnaround":
        """Conjugate update incorporating multiple observation samples."""
        clean = [float(s) for s in observations if math.isfinite(s)]
        updated_samples = list(self._samples) + clean
        prior_std = math.sqrt(max(1e-4, self._prior_var))
        return self.conjugate_update(
            prior_mean=self._prior_mean,
            prior_std=prior_std,
            samples=updated_samples,
            measurement_std=measurement_std,
        )

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mean": self._mean,
            "variance": self._variance,
            "prior_mean": self._prior_mean,
            "prior_var": self._prior_var,
            "samples": list(self._samples),
        }

    @classmethod
    def conjugate_update(
        cls,
        prior_mean: float,
        prior_std: float,
        samples: Sequence[float],
        measurement_std: float = 10.0,
    ) -> "BayesianTurnaround":
        """
        Computes normal-normal conjugate update:
        mu_post = (sigma^2 * mu_0 + n * sigma_0^2 * x_bar) / (n * sigma_0^2 + sigma^2)
        1 / sigma_post^2 = 1 / sigma_0^2 + n / sigma^2
        """
        mu_0 = float(prior_mean)
        sigma_0_sq = max(1e-4, float(prior_std) ** 2)
        clean_samples = [float(s) for s in samples if math.isfinite(s)]
        n = len(clean_samples)

        if n == 0:
            return cls(
                mean=mu_0,
                variance=sigma_0_sq,
                samples=[],
                prior_mean=mu_0,
                prior_var=sigma_0_sq,
            )

        x_bar = float(np.mean(clean_samples))
        if n > 1:
            sample_var = float(np.var(clean_samples, ddof=1))
            sigma_sq = max(sample_var, float(measurement_std) ** 2)
        else:
            sigma_sq = max(1e-4, float(measurement_std) ** 2)

        denom = n * sigma_0_sq + sigma_sq
        mu_post = (sigma_sq * mu_0 + n * sigma_0_sq * x_bar) / denom
        sigma_post_sq = (sigma_0_sq * sigma_sq) / denom

        return cls(
            mean=mu_post,
            variance=sigma_post_sq,
            samples=clean_samples,
            prior_mean=mu_0,
            prior_var=sigma_0_sq,
        )

    def add_sample(self, sample: float, measurement_std: float = 10.0) -> "BayesianTurnaround":
        """Returns a new BayesianTurnaround with the additional observation sample fused."""
        if not math.isfinite(sample):
            return self
        updated_samples = list(self._samples) + [float(sample)]
        prior_std = math.sqrt(self._prior_var)
        return self.conjugate_update(
            prior_mean=self._prior_mean,
            prior_std=prior_std,
            samples=updated_samples,
            measurement_std=measurement_std,
        )

    def update_prior(self, new_prior_mean: float, new_prior_std: float) -> "BayesianTurnaround":
        """Re-evaluates the conjugate posterior with an updated hardware archetype prior."""
        return self.conjugate_update(
            prior_mean=new_prior_mean,
            prior_std=new_prior_std,
            samples=self._samples,
        )
