"""
GraphPath Spatial Kalman Dynamic Estimator
Implements recursive state estimation across shared physical media channels.
Propagates covariance shrinkage from high-confidence anchor nodes to noisy edge links.
"""

import math
from typing import Dict, Any, Optional

C_VACUUM_M_PER_US = 299.792458  # Speed of light in meters per microsecond


class SpatialKalmanEstimator:
    def __init__(self, default_nvp: float = 0.69, default_asic_lat_us: float = 1.2):
        # Global Shared Hyperparameters
        self.nvp = default_nvp
        self.var_nvp = 0.04 ** 2       # Baseline uncertainty in NVP (Cat5e vs Cat6)
        self.asic_latency_us = default_asic_lat_us
        self.var_asic = 0.02 ** 2      # Enterprise switch crossbar jitter (~20ns)

        # State Estimates per Link: link_id -> {"distance": float, "variance": float, "is_anchor": bool}
        self.links: Dict[str, Dict[str, Any]] = {}

    def register_anchor(self, link_id: str, true_distance_m: float, measurement_variance: float = 0.25) -> Dict[str, Any]:
        """
        Ingests a ground-truth physical distance anchor (e.g. Prober patch lead or PoE DC Ohm inversion).
        """
        self.links[link_id] = {
            "distance": float(true_distance_m),
            "variance": float(measurement_variance),
            "is_anchor": True,
            "confidence_pct": round(max(0.0, 100.0 * (1.0 - math.sqrt(measurement_variance) / max(1.0, true_distance_m))), 2)
        }
        return self.links[link_id]

    def calibrate_hyperparameters_from_anchor(
        self,
        link_id: str,
        observed_rtt_us: float,
        target_stack_latency_us: float,
        prober_distance_m: float = 2.0,
        measurement_jitter_us: float = 0.02
    ) -> None:
        """
        Inverts an anchor node observation to tighten global building NVP and switch ASIC latency.
        RTT = 2 * (d_prober + d_target) / v + 2 * t_asic + t_target_stack
        """
        if link_id not in self.links or not self.links[link_id]["is_anchor"]:
            return

        d_target = self.links[link_id]["distance"]
        total_d = prober_distance_m + d_target

        net_flight_rtt_us = observed_rtt_us - target_stack_latency_us - (2.0 * self.asic_latency_us)
        if net_flight_rtt_us <= 0.05:
            return

        v_derived = (2.0 * total_d) / net_flight_rtt_us
        derived_nvp = max(0.55, min(0.85, v_derived / C_VACUUM_M_PER_US))

        # Observation variance on NVP
        var_obs_nvp = ((2.0 * total_d / (C_VACUUM_M_PER_US * (net_flight_rtt_us ** 2))) ** 2) * (measurement_jitter_us ** 2)
        var_obs_nvp = max(0.00005, var_obs_nvp)

        # Kalman scalar update
        kalman_gain_nvp = self.var_nvp / (self.var_nvp + var_obs_nvp)
        self.nvp += kalman_gain_nvp * (derived_nvp - self.nvp)
        self.var_nvp *= (1.0 - kalman_gain_nvp)

    def update_link_rtt(
        self,
        link_id: str,
        observed_rtt_us: float,
        target_stack_latency_us: float,
        measurement_jitter_us: float = 0.05,
        prober_distance_m: float = 2.0
    ) -> Dict[str, Any]:
        """
        Updates link distance estimate using recursive Kalman filtering.
        """
        v_prop = self.nvp * C_VACUUM_M_PER_US

        net_flight_us = max(0.005, observed_rtt_us - target_stack_latency_us - (2.0 * self.asic_latency_us))
        raw_target_dist = max(0.5, ((net_flight_us * v_prop) / 2.0) - prober_distance_m)

        # Measurement variance: combination of timing jitter, NVP uncertainty, and ASIC jitter
        var_measurement = (
            ((v_prop / 2.0) ** 2) * (measurement_jitter_us ** 2) +
            (((net_flight_us / 2.0) * C_VACUUM_M_PER_US) ** 2) * self.var_nvp +
            ((v_prop / 2.0) ** 2) * self.var_asic
        )

        if link_id not in self.links:
            self.links[link_id] = {
                "distance": raw_target_dist,
                "variance": var_measurement,
                "is_anchor": False,
                "confidence_pct": 20.0
            }
        else:
            if self.links[link_id]["is_anchor"]:
                return self.links[link_id]

            prior_dist = self.links[link_id]["distance"]
            prior_var = self.links[link_id]["variance"]

            # Standard 1D Kalman Filter Update
            k_gain = prior_var / (prior_var + var_measurement)
            posterior_dist = prior_dist + k_gain * (raw_target_dist - prior_dist)
            posterior_var = (1.0 - k_gain) * prior_var

            self.links[link_id]["distance"] = posterior_dist
            self.links[link_id]["variance"] = posterior_var

        dist = self.links[link_id]["distance"]
        var = self.links[link_id]["variance"]
        std_dev = math.sqrt(max(1e-6, var))
        
        rel_precision = max(0.0, 1.0 - (std_dev / 15.0))
        confidence = round(max(5.0, min(99.0, 100.0 * rel_precision)), 2)
        self.links[link_id]["confidence_pct"] = confidence

        return self.links[link_id]