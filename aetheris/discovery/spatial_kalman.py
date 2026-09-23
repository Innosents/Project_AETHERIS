"""
Project AETHERIS - Spatial Kalman Dynamic Estimator
Implements recursive state estimation across shared physical media channels.
Propagates covariance shrinkage from high-confidence anchor nodes to noisy edge links.
Supports multi-hop trunk links, inter-switch risers, and media-specific propagation velocities.
"""

import math
from typing import Dict, Any, List, Optional
from aetheris.core.ports.spatial_kalman_port import (
    SpatialKalmanPort,
    AnchorRecord,
    TrunkLinkRecord,
    PathTransitOverhead,
    LinkStateEstimate,
    _MappingCompatibleModel,
)

C_VACUUM_M_PER_US = 299.792458  # Speed of light in meters per microsecond

# Nominal Velocity of Propagation (NVP) presets by physical layer medium
MEDIA_NVP_PRESETS = {
    "COPPER_CAT5E": 0.65,
    "COPPER_CAT6": 0.69,
    "COPPER_CAT6A": 0.71,
    "FIBER_OM3_OM4": 0.66,
    "FIBER_OS2_SMF": 0.67,
}


class SpatialKalmanEstimator(SpatialKalmanPort):
    def __init__(self, default_nvp: float = 0.69, default_asic_lat_us: float = 1.2):
        self.nvp = default_nvp
        self.var_nvp = 0.04 ** 2
        self.asic_latency_us = default_asic_lat_us
        self.var_asic = 0.02 ** 2

        # Link store: link_id -> state dict or record
        self.links: Dict[str, Dict[str, Any]] = {}
        # Trunk links: trunk_id -> state dict or record
        self.trunks: Dict[str, Dict[str, Any]] = {}

    def register_anchor(self, link_id: str, true_distance_m: float, measurement_variance: float = 0.25) -> AnchorRecord:
        """Ingests a ground-truth physical distance anchor."""
        confidence = round(max(0.0, 100.0 * (1.0 - math.sqrt(measurement_variance) / max(1.0, true_distance_m))), 2)
        rec = AnchorRecord(
            distance=float(true_distance_m),
            variance=float(measurement_variance),
            is_anchor=True,
            confidence_pct=confidence,
        )
        self.links[link_id] = {
            "distance": rec.distance,
            "variance": rec.variance,
            "is_anchor": True,
            "confidence_pct": rec.confidence_pct,
        }
        return rec

    def register_trunk_link(
        self,
        trunk_id: str,
        length_m: float,
        media_type: str = "COPPER_CAT6A",
        asic_latency_us: Optional[float] = None,
        variance_m2: float = 0.10
    ) -> TrunkLinkRecord:
        """
        Registers an inter-switch backbone or riser trunk.
        Calculates one-way physical flight time and switch forwarding transit delay.
        """
        nvp = MEDIA_NVP_PRESETS.get(media_type, self.nvp)
        v_prop = nvp * C_VACUUM_M_PER_US
        one_way_flight_us = length_m / v_prop
        hop_asic_us = asic_latency_us if asic_latency_us is not None else self.asic_latency_us

        rec = TrunkLinkRecord(
            length_m=float(length_m),
            media_type=media_type,
            nvp=float(nvp),
            one_way_flight_us=float(one_way_flight_us),
            asic_latency_us=float(hop_asic_us),
            variance_m2=float(variance_m2),
        )
        self.trunks[trunk_id] = {
            "length_m": rec.length_m,
            "media_type": rec.media_type,
            "nvp": rec.nvp,
            "one_way_flight_us": rec.one_way_flight_us,
            "asic_latency_us": rec.asic_latency_us,
            "variance_m2": rec.variance_m2,
        }
        return rec

    def compute_path_transit_overhead(self, path_trunk_ids: List[str]) -> PathTransitOverhead:
        """
        Aggregates round-trip flight and ASIC forwarding overhead across an ordered list of trunk hops.
        Each intermediate switch in the traversal contributes round-trip ASIC latency.
        """
        total_flight_rtt_us = 0.0
        total_asic_rtt_us = 0.0
        accumulated_variance = 0.0

        for trunk_id in path_trunk_ids:
            if trunk_id not in self.trunks:
                raise KeyError(f"Trunk link '{trunk_id}' is not registered in spatial estimator.")
            trunk = self.trunks[trunk_id]
            total_flight_rtt_us += 2.0 * trunk["one_way_flight_us"]
            total_asic_rtt_us += 2.0 * trunk["asic_latency_us"]
            accumulated_variance += trunk["variance_m2"]

        return PathTransitOverhead(
            flight_rtt_us=total_flight_rtt_us,
            asic_rtt_us=total_asic_rtt_us,
            total_overhead_rtt_us=total_flight_rtt_us + total_asic_rtt_us,
            path_variance=accumulated_variance,
        )

    def calibrate_hyperparameters_from_anchor(
        self,
        link_id: str,
        observed_rtt_us: float,
        target_stack_latency_us: float,
        prober_distance_m: float = 2.0,
        measurement_jitter_us: float = 0.02,
        path_trunk_ids: Optional[List[str]] = None
    ) -> None:
        """Inverts an anchor node observation to tighten global building NVP."""
        if link_id not in self.links or not self.links[link_id]["is_anchor"]:
            return

        path_overhead_us = 0.0
        if path_trunk_ids:
            overhead = self.compute_path_transit_overhead(path_trunk_ids)
            path_overhead_us = overhead.total_overhead_rtt_us

        d_target = self.links[link_id]["distance"]
        total_d = prober_distance_m + d_target

        net_flight_rtt_us = observed_rtt_us - target_stack_latency_us - (2.0 * self.asic_latency_us) - path_overhead_us
        if net_flight_rtt_us <= 0.05:
            return

        v_derived = (2.0 * total_d) / net_flight_rtt_us
        derived_nvp = max(0.55, min(0.85, v_derived / C_VACUUM_M_PER_US))

        var_obs_nvp = ((2.0 * total_d / (C_VACUUM_M_PER_US * (net_flight_rtt_us ** 2))) ** 2) * (measurement_jitter_us ** 2)
        var_obs_nvp = max(0.00005, var_obs_nvp)

        kalman_gain_nvp = self.var_nvp / (self.var_nvp + var_obs_nvp)
        self.nvp += kalman_gain_nvp * (derived_nvp - self.nvp)
        self.var_nvp *= (1.0 - kalman_gain_nvp)

    def update_link_rtt(
        self,
        link_id: str,
        observed_rtt_us: float,
        target_stack_latency_us: float,
        measurement_jitter_us: float = 0.05,
        prober_distance_m: float = 2.0,
        path_trunk_ids: Optional[List[str]] = None
    ) -> LinkStateEstimate:
        """
        Updates link distance estimate across single or multi-hop switch topologies.
        Deducts intermediate trunk flight time and transit ASIC latencies.
        """
        v_prop = self.nvp * C_VACUUM_M_PER_US

        path_overhead_us = 0.0
        path_var_m2 = 0.0
        if path_trunk_ids:
            overhead = self.compute_path_transit_overhead(path_trunk_ids)
            path_overhead_us = overhead.total_overhead_rtt_us
            path_var_m2 = overhead.path_variance

        # Net flight dedicated to prober run + target edge drop
        net_flight_us = max(0.005, observed_rtt_us - target_stack_latency_us - (2.0 * self.asic_latency_us) - path_overhead_us)
        raw_target_dist = max(0.5, ((net_flight_us * v_prop) / 2.0) - prober_distance_m)

        var_measurement = (
            ((v_prop / 2.0) ** 2) * (measurement_jitter_us ** 2) +
            (((net_flight_us / 2.0) * C_VACUUM_M_PER_US) ** 2) * self.var_nvp +
            ((v_prop / 2.0) ** 2) * self.var_asic +
            path_var_m2
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
                rec = LinkStateEstimate(
                    distance=self.links[link_id]["distance"],
                    variance=self.links[link_id]["variance"],
                    is_anchor=True,
                    confidence_pct=self.links[link_id]["confidence_pct"]
                )
                return rec

            prior_dist = self.links[link_id]["distance"]
            prior_var = self.links[link_id]["variance"]

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

        return LinkStateEstimate(
            distance=dist,
            variance=var,
            is_anchor=False,
            confidence_pct=confidence
        )


__all__ = [
    "SpatialKalmanEstimator",
    "SpatialKalmanPort",
    "AnchorRecord",
    "TrunkLinkRecord",
    "PathTransitOverhead",
    "LinkStateEstimate",
    "MEDIA_NVP_PRESETS",
    "C_VACUUM_M_PER_US",
    "_MappingCompatibleModel",
]