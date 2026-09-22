"""
Project AETHERIS - Spatial
Translates active round-trip time distributions into bounded 1D physical conductor lengths by subtracting empirical OS stack priors and PHY transceiver latencies from 10th-percentile arrival floors.
Derives spatial variance directly from empirical jitter distributions and maps the resulting dispersion to a sigmoid-bounded Bayesian confidence interval.
"""

import numpy as np
from typing import Dict, List, Tuple

from aetheris.core.ports.spatial_port import SpatialEstimatorPort, SweepEstimateResult

C_VACUUM = 299792458.0

SweepEstimate = SweepEstimateResult


class SpatialEstimator(SpatialEstimatorPort):
    def __init__(self, nvp: float = 0.69, base_phy_latency_sec: float = 1.2e-6):
        self.nvp = nvp
        self.v_prop = nvp * C_VACUUM
        self.base_phy_latency = base_phy_latency_sec

        # Stack delay priors in SI seconds: (delay_mean_sec, delay_var_sec2)
        # Real-world TCP stack turnaround:
        # - Windows Host: ~0.8ms - 1.2ms (or calibrated anchor reference)
        # - Linux Server: ~0.7ms - 1.5ms
        # - Embedded CCTV: ~1.2ms - 5.0ms
        self.stack_priors: Dict[str, Tuple[float, float]] = {
            "WINDOWS_HOST": (9.5e-4, 1.0e-10),   # 950 µs baseline
            "LINUX_SERVER": (1.1e-3, 5.0e-10),   # 1100 µs (1.1 ms) baseline
            "CCTV_VIDEO": (2.5e-3, 1.0e-8),     # 2500 µs (2.5 ms) baseline
            "INDUSTRIAL_OT": (3.0e-4, 1.0e-10),  # 300 µs baseline
            "VOIP_TELEPHONY": (1.0e-3, 1.0e-9),  # 1000 µs baseline
            "NETWORK_INFRASTRUCTURE": (2.0e-4, 1.0e-10),  # 200 µs baseline
            "GENERIC_HOST": (1.0e-3, 1.0e-9),
        }

    def calibrate_anchor(self, archetype: str, observed_rtt_samples: List[float], true_distance_m: float) -> None:
        if not observed_rtt_samples:
            return

        min_rtt = float(np.percentile(observed_rtt_samples, 10))
        physical_flight_time = (2.0 * true_distance_m) / self.v_prop

        total_overhead = max(0.0, min_rtt - physical_flight_time)
        stack_mean = max(0.0, total_overhead - self.base_phy_latency)
        sample_variance = float(np.var(observed_rtt_samples))

        self.stack_priors[archetype] = (stack_mean, max(1.0e-16, sample_variance * 0.05))

    def estimate_node_distance(self, rtt_samples: List[float], archetype: str) -> SweepEstimateResult:
        if not rtt_samples:
            return SweepEstimateResult(0.0, float("inf"), 0.0, 0.0)

        raw_rtts = np.array(rtt_samples, dtype=np.float64)
        filtered_rtt = float(np.percentile(raw_rtts, 10))

        stack_delay, stack_var = self.stack_priors.get(archetype, self.stack_priors["GENERIC_HOST"])
        net_flight_time = filtered_rtt - self.base_phy_latency - stack_delay

        if net_flight_time <= 0:
            return SweepEstimateResult(0.5, 10.0, 75.0, 0.0)

        distance = (net_flight_time * self.v_prop) / 2.0

        # Physical spatial variance derived from empirical RTT jitter
        rtt_sample_var = float(np.var(raw_rtts))
        scale_factor = (self.v_prop / 2.0) ** 2
        # After percentile deconvolution strips macro stack latency,
        # spatial variance is bounded by empirical sample jitter
        effective_jitter_var = rtt_sample_var if len(raw_rtts) > 1 else min(stack_var, 1.0e-14)
        total_spatial_var = effective_jitter_var * scale_factor

        # Standard deviation in meters:
        std_m = float(np.sqrt(max(1e-4, total_spatial_var)))

        # Sigmoid-normalized Bayesian confidence:
        # std_m <= 1.0m yields >90% confidence; std_m ~ 25m yields ~65% confidence
        confidence = float(np.clip(100.0 / (1.0 + (std_m / 45.0) ** 1.5), 1.0, 99.0))

        return SweepEstimateResult(
            distance_m=round(distance, 2),
            variance_m2=round(total_spatial_var, 3),
            confidence_pct=round(confidence, 1),
            net_flight_time_ns=round(net_flight_time * 1e9, 2),
        )
