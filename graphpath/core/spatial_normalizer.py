"""
Project AETHERIS - Spatial Normalization & Bayesian Updating Engine
Translates heterogeneous scan evidence (LLDP-MED civic tags, DHCP Option 82 switch pins,
SNMP Bridge FDB port densities, PoE DC loop resistance / voltage drop, and RTT pulse bounds)
into normalized 1D Gaussian spatial probability densities, fused via Inverse-Variance Weighting.
"""

import numpy as np
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

from graphpath.core.spatial_mcmc import AffineInvariantSpatialMCMC, MCMCResult


@dataclass
class SpatialEvidenceBound:
    distance_estimate_m: float
    variance_m2: float
    confidence_weight: float
    constraint_type: str


class SpatialNormalizationEngine:
    IEEE_802_3_MAX_RUN_M = 100.0

    @classmethod
    def normalize_switchport_fdb(
        cls,
        *args,
        is_trunk: bool = False,
        mac_density: int = 1,
        **kwargs
    ) -> SpatialEvidenceBound:
        trunk = is_trunk
        density = mac_density
        if len(args) == 1:
            if isinstance(args[0], bool):
                trunk = args[0]
        elif len(args) >= 2:
            if isinstance(args[0], str) and isinstance(args[1], bool):
                trunk = args[1]
                if len(args) >= 3 and isinstance(args[2], int):
                    density = args[2]
            elif isinstance(args[0], bool):
                trunk = args[0]
                if isinstance(args[1], int):
                    density = args[1]

        if not trunk and density <= 1:
            return SpatialEvidenceBound(
                distance_estimate_m=18.0,
                variance_m2=150.0,
                confidence_weight=0.85,
                constraint_type="ACCESS_PORT"
            )
        return SpatialEvidenceBound(
            distance_estimate_m=45.0,
            variance_m2=600.0,
            confidence_weight=0.40,
            constraint_type="TRUNK_PORT"
        )

    @classmethod
    def normalize_lldp_med(cls, civic_data: Dict[str, Any]) -> Optional[SpatialEvidenceBound]:
        """Civic room/wall-jack tag locks distance to immediate near-field office run."""
        if civic_data.get("wall_jack") or civic_data.get("room"):
            return SpatialEvidenceBound(
                distance_estimate_m=12.0,
                variance_m2=25.0,
                confidence_weight=0.95,
                constraint_type="HARD_PIN"
            )
        return None

    @classmethod
    def normalize_dhcp_option82(cls, circuit_id: Optional[str] = None, remote_id: Optional[str] = None) -> Optional[SpatialEvidenceBound]:
        """DHCP Option 82 Relay Agent Information locks target to specific switchport drop."""
        if circuit_id or remote_id:
            return SpatialEvidenceBound(
                distance_estimate_m=15.0,
                variance_m2=100.0,
                confidence_weight=0.88,
                constraint_type="HARD_PIN"
            )
        return None

    @classmethod
    def normalize_voltage_drop(cls, v_source: float, v_terminal: float, current_a: float, awg: int = 22) -> Optional[SpatialEvidenceBound]:
        """Converts DC loop resistance to conductor run length."""
        awg_ohms_per_m = {18: 0.0209, 20: 0.0333, 22: 0.0529, 24: 0.0842}
        r_per_m = awg_ohms_per_m.get(awg, 0.0529)
        delta_v = v_source - v_terminal
        if delta_v <= 0 or current_a <= 0:
            return None
        distance_m = delta_v / (2.0 * current_a * r_per_m)
        return SpatialEvidenceBound(
            distance_estimate_m=round(distance_m, 2),
            variance_m2=4.0,
            confidence_weight=0.90,
            constraint_type="VOLTAGE_DROP"
        )

    @classmethod
    def normalize_rtt_pulse(
        cls,
        rtt_samples_us: List[float],
        archetype: str,
        anchor_offset_us: float,
        riser_overhead_us: float = 0.0
    ) -> SpatialEvidenceBound:
        if not rtt_samples_us:
            return SpatialEvidenceBound(50.0, 100.0, 0.0, "RTT_EMPTY")

        # Deduct riser overhead and 5th percentile filters out userspace/softirq scheduling spikes
        effective_samples = [max(0.005, r - riser_overhead_us) for r in rtt_samples_us]
        best_rtt_us = float(np.percentile(effective_samples, 5))
        net_flight_us = max(0.005, best_rtt_us - anchor_offset_us)
        raw_m = (net_flight_us * 1e-6 * 0.69 * 299792458.0) / 2.0

        # Physical boundary clamp: horizontal drops cannot exceed 100m Ethernet standard
        bounded_m = float(np.clip(raw_m, 0.5, cls.IEEE_802_3_MAX_RUN_M))
        jitter_ns = float(np.ptp(effective_samples) * 1000.0)

        # Scale variance from jitter
        var_m2 = float(np.clip((jitter_ns / 1000.0) * 1.5, 2.0, 200.0))
        weight = 0.70 if jitter_ns < 100000.0 else 0.30

        return SpatialEvidenceBound(
            distance_estimate_m=round(bounded_m, 2),
            variance_m2=round(var_m2, 3),
            confidence_weight=weight,
            constraint_type="RTT_PULSE"
        )

    @classmethod
    def fuse_evidence(cls, bounds: List[SpatialEvidenceBound]) -> Dict[str, Any]:
        if not bounds:
            return {"distance_m": 15.0, "variance_m2": 300.0, "confidence_pct": 50.0}

        inv_vars = [b.confidence_weight / max(0.1, b.variance_m2) for b in bounds]
        total_weight = sum(inv_vars)
        fused_dist = sum(b.distance_estimate_m * w for b, w in zip(bounds, inv_vars)) / total_weight
        fused_var = 1.0 / total_weight

        std_m = np.sqrt(fused_var)
        confidence = float(np.clip(100.0 / (1.0 + (std_m / 10.0) ** 1.5), 15.0, 99.0))

        return {
            "distance_m": round(fused_dist, 2),
            "variance_m2": round(fused_var, 3),
            "confidence_pct": round(confidence, 1)
        }

    @classmethod
    def normalize_rtt_mcmc(
        cls,
        rtt_samples_us: List[float],
        archetype: str = "GENERIC_HOST",
        oui: str = "",
        riser_overhead_us: float = 0.0
    ) -> SpatialEvidenceBound:
        """
        Uses Affine-Invariant Ensemble MCMC to deconvolve physical cable distance
        and kernel turnaround latency without hardcoded heuristic clamps.
        """
        if not rtt_samples_us:
            return SpatialEvidenceBound(15.0, 300.0, 0.20, "MCMC_EMPTY")
        sampler = AffineInvariantSpatialMCMC()
        res = sampler.sample(
            rtt_samples_us,
            archetype=archetype,
            oui=oui,
            riser_overhead_us=riser_overhead_us
        )
        return SpatialEvidenceBound(
            distance_estimate_m=res.distance_m,
            variance_m2=res.variance_m2,
            confidence_weight=float(np.clip(res.confidence_pct / 100.0, 0.2, 0.9)),
            constraint_type="MCMC_POSTERIOR"
        )

    @classmethod
    def normalize_wireless_airlink(cls, jitter_std_ns: float = 1200.0) -> SpatialEvidenceBound:
        """
        Bounds 802.11 wireless airlinks.
        Contention delay and air interface turnaround must not be interpreted
        as hundreds of meters of copper run; bounds estimated distance to local AP cell radius.
        """
        return SpatialEvidenceBound(
            distance_estimate_m=12.0,
            variance_m2=200.0,
            confidence_weight=0.35,
            constraint_type="WIRELESS_AIRLINK"
        )


class PhysicalMediumClassifier:
    """
    Classifies physical connection medium using arrival jitter distribution.
    Differentiates copper PHYs (<500ns jitter) from 802.11 wireless contention (>1us jitter).
    """
    JITTER_THRESHOLD_NS = 1000.0  # 1 microsecond

    @classmethod
    def classify_medium(cls, rtt_samples_ns: List[float]) -> Dict[str, Any]:
        if len(rtt_samples_ns) < 2:
            return {
                "medium": "UNKNOWN",
                "confidence": 0.50,
                "is_wireless": False,
                "display": "Unknown Medium",
                "jitter_std_ns": 0.0
            }

        arr = np.array(rtt_samples_ns)
        jitter_std = float(np.std(arr))

        if jitter_std > cls.JITTER_THRESHOLD_NS:
            return {
                "medium": "WIRELESS_802_11",
                "jitter_std_ns": jitter_std,
                "is_wireless": True,
                "display": "WLAN (802.11 AirLink)"
            }
        else:
            return {
                "medium": "COPPER_ETHERNET",
                "jitter_std_ns": jitter_std,
                "is_wireless": False,
                "display": "Copper (Cat5e/Cat6 Drop)"
            }

