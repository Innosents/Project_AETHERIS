"""
GraphPath Discovery Engine
Orchestrates active discovery sweeps, Bayesian evidence fusion,
passive L2 CDP/LLDP switch-tree mapping, raw socket Npcap packet tapping,
and recursive Kalman spatial distance estimation.
"""

from typing import Dict, Any, List, Optional
from graphpath.topology.graph_store import GraphStore
from graphpath.core.spatial_bayesian import BayesianEvidenceFusion
from graphpath.discovery.spatial_kalman import SpatialKalmanEstimator
from graphpath.discovery.passive_l2_listener import PassiveL2TopologyListener
from graphpath.discovery.raw_packet_tap import RawPacketTap


class DiscoveryEngine:
    ARCHETYPE_STACK_LATENCIES_US = {
        "WINDOWS_HOST": 22.1,
        "VOIP_TELEPHONY": 16.5,
        "INDUSTRIAL_OT": 8.4,
        "CCTV_VIDEO": 18.2,
        "NETWORK_INFRASTRUCTURE": 10.0,
        "LINUX_SERVER": 14.2,
    }

    def __init__(
        self,
        graph_store: Optional[GraphStore] = None,
        prober_lead_m: float = 2.0,
        interface: Optional[str] = None,
        enable_tap: bool = False
    ):
        self.graph = graph_store or GraphStore()
        self.prober_lead_m = prober_lead_m
        self.kalman = SpatialKalmanEstimator(default_nvp=0.69, default_asic_lat_us=1.2)
        self.switch_id = "default_core_switch"
        self.l2_listener = PassiveL2TopologyListener(on_switch_discovered=self._handle_switch_discovered)

        # Low-level raw packet tap
        self.packet_tap = RawPacketTap(
            interface=interface,
            on_packet_received=self.ingest_l2_packet
        ) if enable_tap else None

    def start_network_tap(self) -> None:
        """Activates promiscuous packet capture for L2 discovery and RTT tapping."""
        if self.packet_tap:
            self.packet_tap.start_listener()

    def stop_network_tap(self) -> None:
        """Deactivates packet capture."""
        if self.packet_tap:
            self.packet_tap.stop_listener()

    def _handle_switch_discovered(self, switch_data: Dict[str, Any]) -> None:
        """Callback invoked when a CDP or LLDP packet is intercepted."""
        sw_id = switch_data["switch_id"]
        
        if self.switch_id == "default_core_switch":
            self.switch_id = sw_id

        self.graph.upsert_node(sw_id, {
            "type": "SWITCH",
            "protocol": switch_data.get("protocol"),
            "chassis_id": switch_data.get("chassis_id"),
            "system_name": switch_data.get("system_name"),
            "port_id": switch_data.get("port_id"),
            "management_ip": switch_data.get("management_ip"),
            "archetype": "NETWORK_INFRASTRUCTURE"
        })

    def ingest_l2_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """Passively processes an ingested raw L2 frame."""
        return self.l2_listener.process_packet(packet)

    def probe_and_calibrate_endpoint(
        self,
        target_ip: str,
        target_port: int,
        node_id: str,
        observed_telemetry_keys: List[str],
        burst_count: int = 5,
        parent_switch_id: Optional[str] = None,
        path_trunk_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Fires hardware-timed RTT bursts via RawPacketTap, fuses evidence,
        and estimates physical cable length into GraphStore.
        """
        if self.packet_tap:
            rtt_samples = self.packet_tap.execute_rtt_pulse_burst(
                target_ip=target_ip,
                target_port=target_port,
                burst_count=burst_count
            )
        else:
            rtt_samples = []

        return self.process_discovered_node(
            node_id=node_id,
            observed_telemetry_keys=observed_telemetry_keys,
            rtt_samples_us=rtt_samples,
            parent_switch_id=parent_switch_id,
            path_trunk_ids=path_trunk_ids
        )

    def register_switch_trunk(
        self,
        upstream_switch_id: str,
        downstream_switch_id: str,
        length_m: float,
        media_type: str = "COPPER_CAT6A",
        asic_latency_us: Optional[float] = None
    ) -> str:
        trunk_id = f"{upstream_switch_id}->{downstream_switch_id}"
        self.kalman.register_trunk_link(
            trunk_id=trunk_id,
            length_m=length_m,
            media_type=media_type,
            asic_latency_us=asic_latency_us
        )
        self.graph.add_edge(
            source=upstream_switch_id,
            target=downstream_switch_id,
            edge_type="TRUNK_RISER",
            distance_m=length_m,
            variance_m2=0.10,
            confidence_pct=99.0,
            is_anchor=True,
            media_type=media_type
        )
        return trunk_id

    def register_switch_anchor(self, switch_id: str, anchor_target_id: str, true_distance_m: float, measurement_variance: float = 0.25) -> None:
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
        known_distance_m: Optional[float] = None,
        parent_switch_id: Optional[str] = None,
        path_trunk_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        target_switch = parent_switch_id or self.switch_id
        link_id = f"{target_switch}->{node_id}"

        posterior_probs = BayesianEvidenceFusion.fuse_evidence(observed_telemetry_keys)
        top_archetype = max(posterior_probs, key=posterior_probs.get)
        stack_latency_us = self.ARCHETYPE_STACK_LATENCIES_US.get(top_archetype, 15.0)

        self.graph.upsert_node(node_id, {
            "archetype": top_archetype,
            "posteriors": posterior_probs,
            "stack_latency_us": stack_latency_us
        })

        if is_anchor and known_distance_m is not None:
            self.register_switch_anchor(target_switch, node_id, known_distance_m)
            if rtt_samples_us:
                min_rtt = min(rtt_samples_us)
                self.kalman.calibrate_hyperparameters_from_anchor(
                    link_id=link_id,
                    observed_rtt_us=min_rtt,
                    target_stack_latency_us=stack_latency_us,
                    prober_distance_m=self.prober_lead_m,
                    path_trunk_ids=path_trunk_ids
                )
            spatial_state = self.kalman.links[link_id]
        else:
            spatial_state = None
            for rtt in rtt_samples_us:
                spatial_state = self.kalman.update_link_rtt(
                    link_id=link_id,
                    observed_rtt_us=rtt,
                    target_stack_latency_us=stack_latency_us,
                    measurement_jitter_us=0.05,
                    prober_distance_m=self.prober_lead_m,
                    path_trunk_ids=path_trunk_ids
                )

            if spatial_state:
                self.graph.add_edge(
                    source=target_switch,
                    target=node_id,
                    edge_type="ETHERNET_LINK",
                    distance_m=round(spatial_state["distance"], 2),
                    variance_m2=round(spatial_state["variance"], 4),
                    confidence_pct=spatial_state["confidence_pct"],
                    is_anchor=False
                )

        return {
            "node_id": node_id,
            "parent_switch": target_switch,
            "archetype": top_archetype,
            "spatial_state": spatial_state,
            "global_nvp": self.kalman.nvp
        }