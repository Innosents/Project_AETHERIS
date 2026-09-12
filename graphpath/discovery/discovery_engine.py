"""
GraphPath Discovery Engine
Orchestrates active discovery sweeps, Bayesian evidence fusion,
and recursive Kalman spatial distance estimation into GraphStore.
"""

from typing import Dict, Any, List, Optional
from graphpath.topology.graph_store import GraphStore
from graphpath.core.spatial_bayesian import BayesianEvidenceFusion
from graphpath.discovery.spatial_kalman import SpatialKalmanEstimator
from graphpath.discovery.advanced_spatial_prober import AdvancedSpatialProber


class DiscoveryEngine:
    # Empirical kernel/firmware stack turnaround delays indexed by Archetype
    ARCHETYPE_STACK_LATENCIES_US = {
        "WINDOWS_HOST": 22.1,
        "VOIP_TELEPHONY": 16.5,
        "INDUSTRIAL_OT": 8.4,
        "CCTV_VIDEO": 18.2,
        "NETWORK_INFRASTRUCTURE": 10.0,
        "LINUX_SERVER": 14.2,
    }

    def __init__(self, graph_store: Optional[GraphStore] = None, prober_lead_m: float = 2.0):
        self.graph = graph_store or GraphStore()
        self.prober_lead_m = prober_lead_m
        self.kalman = SpatialKalmanEstimator(default_nvp=0.69, default_asic_lat_us=1.2)
        self.switch_id = "default_core_switch"

    def register_switch_anchor(self, switch_id: str, anchor_target_id: str, true_distance_m: float, measurement_variance: float = 0.25) -> None:
        """Pins a high-confidence anchor (e.g. PoE high-draw camera or known patch drop)."""
        link_id = f"{switch_id}->{anchor_target_id}"
        self.kalman.register_anchor(link_id, true_distance_m=true_distance_m, measurement_variance=measurement_variance)
        
        self.graph.add_edge(
            source=switch_id,
            target=anchor_target_id,
            edge_type="ETHERNET_ANCHOR",
            distance_m=true_distance_m,
            variance_m2=measurement_variance,
            confidence_pct=98.0,
            is_anchor=True
        )

    def process_discovered_node(
        self,
        node_id: str,
        observed_telemetry_keys: List[str],
        rtt_samples_us: List[float],
        is_anchor: bool = False,
        known_distance_m: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Executes evidence fusion, estimates physical cable length via Kalman state,
        and pushes spatial state to GraphStore.
        """
        # 1. Classify Archetype via Bayesian Posterior Simplices
        posterior_probs = BayesianEvidenceFusion.fuse_evidence(observed_telemetry_keys)
        top_archetype = max(posterior_probs, key=posterior_probs.get)
        
        # Ingest inferred stack turnaround delay
        stack_latency_us = self.ARCHETYPE_STACK_LATENCIES_US.get(top_archetype, 15.0)

        # 2. Register Node into GraphStore
        self.graph.upsert_node(node_id, {
            "archetype": top_archetype,
            "posteriors": posterior_probs,
            "stack_latency_us": stack_latency_us
        })

        link_id = f"{self.switch_id}->{node_id}"

        # 3. Spatial Resolution
        if is_anchor and known_distance_m is not None:
            self.register_switch_anchor(self.switch_id, node_id, known_distance_m)
            # Calibrate global NVP using the anchor's minimum clean RTT sample
            if rtt_samples_us:
                min_rtt = min(rtt_samples_us)
                self.kalman.calibrate_hyperparameters_from_anchor(
                    link_id=link_id,
                    observed_rtt_us=min_rtt,
                    target_stack_latency_us=stack_latency_us,
                    prober_distance_m=self.prober_lead_m
                )
            spatial_state = self.kalman.links[link_id]
        else:
            # Recursive update across observed RTT burst pulses
            spatial_state = None
            for rtt in rtt_samples_us:
                spatial_state = self.kalman.update_link_rtt(
                    link_id=link_id,
                    observed_rtt_us=rtt,
                    target_stack_latency_us=stack_latency_us,
                    measurement_jitter_us=0.05,
                    prober_distance_m=self.prober_lead_m
                )

            if spatial_state:
                self.graph.add_edge(
                    source=self.switch_id,
                    target=node_id,
                    edge_type="ETHERNET_LINK",
                    distance_m=round(spatial_state["distance"], 2),
                    variance_m2=round(spatial_state["variance"], 4),
                    confidence_pct=spatial_state["confidence_pct"],
                    is_anchor=False
                )

        return {
            "node_id": node_id,
            "archetype": top_archetype,
            "spatial_state": spatial_state,
            "global_nvp": self.kalman.nvp
        }