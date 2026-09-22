import time
import logging
from typing import Dict, Any, Optional
from pydantic import ValidationError

# Domain & Infrastructure Imports
from aetheris.core.ports.inbound import BayesianTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

# Legacy Engine Stubs (Representing the existing implementations)
# from aetheris.legacy.capture import SpanCaptureEngine
# from aetheris.legacy.prober import AdvancedSpatialProber

logger = logging.getLogger("aetheris.adapters.translator")

class SpatialProberAdapter:
    """
    Translates asynchronous active probes into strict BayesianTelemetryPort schemas.
    Calculates localized Dirichlet probabilities from raw temporal variance.
    """
    def __init__(self, event_bus: MemuraiEventBus):
        self.bus = event_bus
        self.queue_name = "aetheris:telemetry:bayesian_states"
        # Local state buffer for Bayesian prior calculation
        self._temporal_baselines: Dict[str, float] = {}

    def _compute_splice_probability(self, mac: str, current_jitter_ms: float) -> float:
        """
        Transforms raw latency into a 0.0-1.0 Dirichlet probability tensor.
        A sudden spike in jitter exponentially increases the splice probability.
        """
        if mac not in self._temporal_baselines:
            self._temporal_baselines[mac] = current_jitter_ms
            return 0.01  # Baseline initialization confidence

        baseline = self._temporal_baselines[mac]
        deviation = abs(current_jitter_ms - baseline)
        
        # Exponential update to the baseline (alpha = 0.1)
        self._temporal_baselines[mac] = (0.9 * baseline) + (0.1 * current_jitter_ms)

        # Sigmoid activation mapping deviation to probability
        probability = min(1.0, deviation / (baseline + 1e-9))
        return round(probability, 4)

    async def ingest_and_publish(self, raw_probe_data: Dict[str, Any]) -> None:
        """
        Filters raw prober output, maps to Hexagonal Port, and pushes to Memurai.
        """
        try:
            mac_address = raw_probe_data.get("mac", "").upper()
            
            # Enforce absolute positive bounds for CPU clock anomalies
            raw_latency = abs(raw_probe_data.get("latency_ns", 0.0) / 1_000_000.0)
            
            probability = self._compute_splice_probability(mac_address, raw_latency)

            # Strict Port Validation Matrix
            validated_payload = BayesianTelemetryPort(
                hardware_id=mac_address,
                splice_probability=probability,
                spatial_jitter_ms=round(raw_latency, 4)
            )

            await self.bus.push_telemetry(
                self.queue_name, 
                validated_payload.model_dump()
            )
            
        except ValidationError as e:
            logger.error("Prober telemetry failed mathematical bounds: %s", e.errors())
        except KeyError as e:
            logger.error("Malformed prober payload, missing key: %s", e)