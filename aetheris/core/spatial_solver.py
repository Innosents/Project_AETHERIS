"""
Project AETHERIS - Multi-Anchor Weighted Least-Squares (WLS) Spatial Solver
Decouples asymmetric switch ASIC / PHY serialization delays from physical
transmission line Nominal Velocity of Propagation (NVP) via overdetermined
linear system calibration across physical anchor drops.

Mathematical Formulation:
  y_i = RTT_i - t_{kernel, i} = t_{switch} + (2 / (NVP * c)) * d_i + epsilon_i
  Matrix system: y = A * x + epsilon, where row i of A is [1.0, d_i].
  Parameter vector: x = [t_{switch}, x_2]^T, where x_2 = 2 / (NVP * c).
  Weight matrix: W = diag(w_1, ..., w_m), where w_i = 1 / max(sigma_{jitter, i}^2, 1e-18).
  WLS solution: x_hat = (A^T W A)^{-1} A^T W y via SVD-based np.linalg.lstsq.
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

from aetheris.core.ports.spatial_solver_port import (
    SpatialSolverPort,
    SpatialSolverResultModel,
    SpatialDistanceEstimateModel,
)
from aetheris.core.probers.sanitization import sanitize_prober_payload

# Physical constants for twisted-pair copper transmission lines
C_VACUUM: float = 299792458.0  # Speed of light in vacuum (m/s)
DEFAULT_NOMINAL_NVP: float = 0.69  # Nominal Cat5e/Cat6 velocity factor (0.69c)
MIN_PHYSICAL_NVP: float = 0.50  # Lower physical bound (high-dielectric insulation)
MAX_PHYSICAL_NVP: float = 0.85  # Upper physical bound (foamed FEP dielectric)
MIN_VARIANCE_S2: float = 1.0e-18  # Numerical floor for jitter variance (1 ps^2)

SpatialSolverResult = SpatialSolverResultModel
SpatialDistanceEstimate = SpatialDistanceEstimateModel


class SpatialSolver(SpatialSolverPort):
    """
    Overdetermined multi-anchor Weighted Least-Squares (WLS) spatial physics engine.
    Calibrates lumped switch latency and transmission line slowness, and provides
    calibrated line distance estimations.
    """

    def __init__(
        self,
        nominal_nvp: float = DEFAULT_NOMINAL_NVP,
        base_switch_latency_s: float = 1.2e-6
    ):
        self.nominal_nvp: float = float(nominal_nvp)
        self.nominal_v_prop: float = self.nominal_nvp * C_VACUUM
        self.nominal_slowness_x2: float = 2.0 / self.nominal_v_prop
        self.base_switch_latency_s: float = float(base_switch_latency_s)

        # Dynamic calibrated state
        self.calibrated_nvp: float = self.nominal_nvp
        self.calibrated_switch_latency_s: float = self.base_switch_latency_s
        self.calibrated_slowness_x2: float = self.nominal_slowness_x2
        self.is_calibrated: bool = False
        self.last_calibration: Optional[Dict[str, Any]] = None

    def calibrate_multi_anchor(
        self,
        anchor_profiles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Executes multi-anchor WLS calibration.
        Accepts a list of anchor dictionaries containing:
          - ip: str
          - mac: Optional[str]
          - known_distance_m: float
          - rtt_samples: Optional[List[float]] (in seconds or microseconds)
          - rtt: Optional[float]
          - t_kernel: Optional[float] (in seconds or microseconds)
          - jitter_ns: Optional[float]
        """
        if not anchor_profiles:
            result = SpatialSolverResult(
                calibrated_nvp=self.nominal_nvp,
                calibrated_switch_latency_s=self.base_switch_latency_s,
                slowness_x2=self.nominal_slowness_x2,
                residuals=[],
                anchor_count=0,
                wls_confidence=50.0,
                is_clamped=False,
                rmse_ns=0.0,
                fallback_nominal=True
            )
            self.last_calibration = result.to_dict()
            return self.last_calibration

        # Filter valid anchor inputs
        parsed_anchors = []
        for p in anchor_profiles:
            known_d = float(p.get("known_distance_m", p.get("known_m", 0.0)))
            if known_d <= 0.0:
                continue

            # Extract RTT
            rtt_samples = p.get("rtt_samples", [])
            if isinstance(rtt_samples, (list, tuple, np.ndarray)) and len(rtt_samples) > 0:
                samples = [float(s) for s in rtt_samples if s > 0.0]
                if not samples:
                    continue
                # 10th percentile deconvolution to eliminate userspace scheduling spikes
                rtt_val = float(np.percentile(samples, 10))
                sample_var = float(np.var(samples)) if len(samples) > 1 else 0.0
            elif "rtt" in p and p["rtt"] is not None:
                rtt_val = float(p["rtt"])
                sample_var = 0.0
            elif "min_rtt_us" in p and p["min_rtt_us"] is not None:
                rtt_val = float(p["min_rtt_us"]) * 1e-6
                sample_var = 0.0
            else:
                continue

            # Unit normalisation: if RTT > 10.0, it was provided in microseconds
            rtt_s = rtt_val * 1e-6 if rtt_val > 10.0 else rtt_val

            # Target kernel turnaround
            tk = float(p.get("t_kernel", p.get("t_kernel_us", p.get("converged_kernel_us", 0.0))))
            tk_s = tk * 1e-6 if tk > 1.0 else tk

            # Jitter / noise variance in seconds squared
            jitter_ns = p.get("jitter_ns", p.get("jitter_us", None))
            if jitter_ns is not None:
                # If jitter_us was passed, convert to ns first
                if "jitter_us" in p and "jitter_ns" not in p:
                    j_ns = float(p["jitter_us"]) * 1000.0
                else:
                    j_ns = float(jitter_ns)
                sigma_s = max(1e-10, j_ns * 1e-9)
            elif sample_var > 0.0:
                sigma_s = math.sqrt(sample_var)
                if rtt_val > 10.0:
                    sigma_s *= 1e-6
            else:
                sigma_s = 1.0e-9

            variance_s2 = max(sigma_s ** 2, MIN_VARIANCE_S2)
            y_obs = max(0.0, rtt_s - tk_s)

            parsed_anchors.append({
                "d": known_d,
                "y": y_obs,
                "var_s2": variance_s2,
                "sigma_s": sigma_s
            })

        m = len(parsed_anchors)
        if m == 0:
            result = SpatialSolverResult(
                calibrated_nvp=self.nominal_nvp,
                calibrated_switch_latency_s=self.base_switch_latency_s,
                slowness_x2=self.nominal_slowness_x2,
                residuals=[],
                anchor_count=0,
                wls_confidence=50.0,
                is_clamped=False,
                rmse_ns=0.0,
                fallback_nominal=True
            )
            self.last_calibration = result.to_dict()
            return self.last_calibration

        # -----------------------------------------------------------------------
        # Case A: Single Anchor Fallback (m = 1)
        # -----------------------------------------------------------------------
        if m == 1:
            a0 = parsed_anchors[0]
            t_flight = (2.0 * a0["d"]) / self.nominal_v_prop
            t_switch = max(0.0, a0["y"] - t_flight)
            res_val = 0.0

            result = SpatialSolverResult(
                calibrated_nvp=self.nominal_nvp,
                calibrated_switch_latency_s=t_switch,
                slowness_x2=self.nominal_slowness_x2,
                residuals=[res_val],
                anchor_count=1,
                wls_confidence=92.0,
                is_clamped=False,
                rmse_ns=0.0,
                fallback_nominal=True
            )
            self._apply_calibration_state(result)
            return self.last_calibration

        # -----------------------------------------------------------------------
        # Case B: Collinear / Degenerate Anchor Geometry Check (Δd < 0.5m)
        # -----------------------------------------------------------------------
        distances = [a["d"] for a in parsed_anchors]
        if max(distances) - min(distances) < 0.5:
            # Cannot decouple slope with identical distances; fall back to nominal NVP
            switch_latencies = [max(0.0, a["y"] - ((2.0 * a["d"]) / self.nominal_v_prop)) for a in parsed_anchors]
            avg_switch = float(np.mean(switch_latencies))
            resids = [(a["y"] - (avg_switch + (2.0 * a["d"] / self.nominal_v_prop))) * 1e9 for a in parsed_anchors]
            rmse = float(np.sqrt(np.mean(np.array(resids) ** 2)))

            result = SpatialSolverResult(
                calibrated_nvp=self.nominal_nvp,
                calibrated_switch_latency_s=avg_switch,
                slowness_x2=self.nominal_slowness_x2,
                residuals=resids,
                anchor_count=m,
                wls_confidence=85.0,
                is_clamped=False,
                rmse_ns=rmse,
                fallback_nominal=True
            )
            self._apply_calibration_state(result)
            return self.last_calibration

        # -----------------------------------------------------------------------
        # Case C: Overdetermined Weighted Least-Squares (m >= 2)
        # -----------------------------------------------------------------------
        # Formulate y = A * x + epsilon
        # A_i = [1.0, d_i], y_i = observed propagation time
        A = np.zeros((m, 2), dtype=np.float64)
        y = np.zeros(m, dtype=np.float64)
        weights = np.zeros(m, dtype=np.float64)

        for i, a in enumerate(parsed_anchors):
            A[i, 0] = 1.0
            A[i, 1] = a["d"]
            y[i] = a["y"]
            weights[i] = 1.0 / a["var_s2"]

        # Scale system by sqrt(W) for SVD solution
        sqrt_W = np.sqrt(weights)
        A_w = A * sqrt_W[:, np.newaxis]
        y_w = y * sqrt_W

        # Solve weighted normal system
        x_hat, _, _, _ = np.linalg.lstsq(A_w, y_w, rcond=None)
        t_switch_raw = float(x_hat[0])
        x2_raw = float(x_hat[1])

        # Enforce physical constraints on switch latency
        t_switch = max(0.0, t_switch_raw)

        # Extract empirical NVP
        if x2_raw > 0.0:
            nvp_empirical = 2.0 / (x2_raw * C_VACUUM)
        else:
            nvp_empirical = self.nominal_nvp

        # Bounds clamp to physical copper limits [0.50, 0.85]
        is_clamped = False
        if nvp_empirical < MIN_PHYSICAL_NVP:
            calibrated_nvp = MIN_PHYSICAL_NVP
            is_clamped = True
        elif nvp_empirical > MAX_PHYSICAL_NVP:
            calibrated_nvp = MAX_PHYSICAL_NVP
            is_clamped = True
        else:
            calibrated_nvp = nvp_empirical

        # Effective slowness parameter under clamped or solved NVP
        effective_x2 = 2.0 / (calibrated_nvp * C_VACUUM)

        # Residuals computation: y_pred = t_switch + effective_x2 * d
        y_pred = t_switch + effective_x2 * A[:, 1]
        raw_residuals_s = y - y_pred
        residuals_ns = [float(r * 1e9) for r in raw_residuals_s]

        # Weighted RMSE in seconds
        weighted_sse = float(np.sum(weights * (raw_residuals_s ** 2)))
        total_weight = float(np.sum(weights))
        rmse_s = math.sqrt(weighted_sse / max(total_weight, 1e-12))
        rmse_ns = rmse_s * 1e9

        # Sigmoid-normalized Bayesian confidence
        base_confidence = 100.0 / (1.0 + (rmse_s / 40.0e-9) ** 1.8)
        if is_clamped:
            base_confidence = min(base_confidence, 82.0)
        confidence = float(np.clip(base_confidence, 50.0, 99.9))

        result = SpatialSolverResult(
            calibrated_nvp=calibrated_nvp,
            calibrated_switch_latency_s=t_switch,
            slowness_x2=effective_x2,
            residuals=residuals_ns,
            anchor_count=m,
            wls_confidence=confidence,
            is_clamped=is_clamped,
            rmse_ns=rmse_ns,
            fallback_nominal=False
        )
        self._apply_calibration_state(result)
        return self.last_calibration

    def calibrate_baseline(
        self,
        anchor_profiles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Alias for calibrate_multi_anchor for API symmetry."""
        return self.calibrate_multi_anchor(anchor_profiles)

    def _apply_calibration_state(self, result: SpatialSolverResult) -> None:
        """Stores calibrated values into active solver state."""
        self.calibrated_nvp = float(result.calibrated_nvp)
        self.calibrated_switch_latency_s = float(result.calibrated_switch_latency_s)
        self.calibrated_slowness_x2 = float(result.slowness_x2)
        self.is_calibrated = True
        self.last_calibration = result.to_dict()

    def estimate_distance(
        self,
        rtt_samples: Union[List[float], float],
        t_kernel: float,
        jitter_ns: Optional[float] = None,
        overlay_flags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Derives physical cable conductor length using the dynamically calibrated
        two-way transmission line slowness parameter (x_2).
        d = tau_flight / x_2
        When overlay_flags indicate SD-WAN or Cloud VPN overlays, suppresses copper
        clamping and flags is_virtual_overlay = True.
        """
        flags = overlay_flags or []
        is_sdwan = "FLAG_SD_WAN_TUNNEL_OVERLAY" in flags
        is_cloud_vpn = "FLAG_CLOUD_VPN_ENCAPSULATED" in flags
        is_virtual = is_sdwan or is_cloud_vpn
        overlay_type = "SD_WAN_TUNNEL" if is_sdwan else ("CLOUD_VPN_ENCAPSULATED" if is_cloud_vpn else None)

        # Parse RTT samples
        if isinstance(rtt_samples, (list, tuple, np.ndarray)):
            samples = [float(s) for s in rtt_samples if s > 0.0]
            if not samples:
                return SpatialDistanceEstimate(
                    0.5, 100.0, 0.0, 0.0,
                    is_virtual_overlay=is_virtual,
                    virtual_overlay_type=overlay_type,
                    overlay_flags=flags
                ).to_dict()
            rtt_val = float(np.percentile(samples, 10))
            sample_std = float(np.std(samples)) if len(samples) > 1 else 0.0
        else:
            rtt_val = float(rtt_samples)
            sample_std = 0.0

        # Normalize units to seconds
        rtt_s = rtt_val * 1e-6 if rtt_val > 10.0 else rtt_val
        tk_s = float(t_kernel) * 1e-6 if float(t_kernel) > 1.0 else float(t_kernel)

        # Cable flight time: tau_flight = RTT - t_kernel - t_switch
        net_flight_time_s = max(0.0, rtt_s - tk_s - self.calibrated_switch_latency_s)

        if net_flight_time_s <= 0.0:
            return SpatialDistanceEstimate(
                0.5, 20.0, 50.0, 0.0,
                is_virtual_overlay=is_virtual,
                virtual_overlay_type=overlay_type,
                overlay_flags=flags
            ).to_dict()

        # Distance derived via calibrated line slowness: d = tau_flight / x_2
        raw_distance_m = net_flight_time_s / self.calibrated_slowness_x2
        if is_virtual:
            # Virtual overlay bypasses 100m copper channel boundary
            distance_m = float(raw_distance_m)
        else:
            distance_m = float(np.clip(raw_distance_m, 0.5, 100.0))  # IEEE 802.3 clamp

        # Variance propagation: Var(d) = Var(t) / x_2^2
        if jitter_ns is not None:
            sigma_t = max(1e-10, float(jitter_ns) * 1e-9)
        elif sample_std > 0.0:
            sigma_t = sample_std * 1e-6 if rtt_val > 10.0 else sample_std
        else:
            sigma_t = 2.0e-9

        sigma_d = sigma_t / self.calibrated_slowness_x2
        variance_m2 = float(np.clip(sigma_d ** 2, 1e-4, 100.0))

        # Sigmoid-normalized Bayesian confidence
        conf = float(np.clip(100.0 / (1.0 + (math.sqrt(variance_m2) / 3.0) ** 1.5), 10.0, 99.0))
        net_flight_ns = net_flight_time_s * 1e9

        res = SpatialDistanceEstimate(
            distance_m=distance_m,
            variance_m2=variance_m2,
            confidence_pct=conf,
            net_flight_time_ns=net_flight_ns,
            is_virtual_overlay=is_virtual,
            virtual_overlay_type=overlay_type,
            overlay_flags=flags
        )
        return res.to_dict()
