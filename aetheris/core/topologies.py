"""
Project AETHERIS - Topologies and Graph Projection.
"""
import math
import re

import networkx as nx
from typing import Dict, List, Any, Optional

from aetheris.core.ports.topologies_port import TopologyProjectionPort

Endpoint: str = "Endpoint"
Unmanaged_Switch: str = "Unmanaged_Switch"


def project_topology(self, fused_matrix: Optional[Dict[str, Any]] = None) -> nx.DiGraph:
    """
    Fuses multiplexed telemetry matrices into a directional graph (DiGraph).
    Identifies convergence clusters where multiple MAC endpoints share identical
    TTL hop distances and STP root_path_cost integers, injecting an Unmanaged_Switch
    at the convergence boundary. Redraws edges with absolute path cost weighting.
    """
    matrix = fused_matrix if fused_matrix is not None else self.fused_matrix
    if not matrix:
        matrix = {
            "chassis_intelligence": self.chassis_matrix,
            "spanning_tree_intelligence": self.stp_matrix,
            "multicast_identity": self.multicast_matrix,
            "l3_hop_intelligence": self.ttl_matrix,
        }

    chassis_data = matrix.get("chassis_intelligence") or matrix.get("chassis_matrix") or self.chassis_matrix or {}
    stp_data = matrix.get("spanning_tree_intelligence") or matrix.get("stp_matrix") or self.stp_matrix or {}
    ttl_data = matrix.get("l3_hop_intelligence") or matrix.get("ttl_matrix") or self.ttl_matrix or {}
    multicast_data = matrix.get("multicast_identity") or matrix.get("multicast_matrix") or self.multicast_matrix or {}

    # 1. Base initialization: Create core switch and register root node
    self.graph = nx.DiGraph()
    core_switch = "Core_Distribution_Switch"
    self.graph.add_node(core_switch, type="switch", node_type="Core_Switch", label=core_switch)

    # 2. Extract and index all candidate endpoints
    all_endpoints = set()
    for src_dict in (chassis_data, stp_data, ttl_data, multicast_data):
        if isinstance(src_dict, dict):
            all_endpoints.update(src_dict.keys())

    endpoint_metadata = []
    for ep in all_endpoints:
        # Extract STP path cost (supporting root_path_cost, pathcost, path_cost)
        root_path_cost = None
        stp_entry = stp_data.get(ep, {}) if isinstance(stp_data, dict) else {}
        if isinstance(stp_entry, dict):
            for key in ("root_path_cost", "pathcost", "path_cost"):
                if key in stp_entry and stp_entry[key] is not None:
                    try:
                        root_path_cost = int(stp_entry[key])
                        break
                    except (ValueError, TypeError):
                        pass

        # Extract L3 TTL hop count
        ttl_hop = None
        if isinstance(ttl_data, dict):
            ttl_val = ttl_data.get(ep)
            if ttl_val is None and isinstance(stp_entry, dict):
                ip_cand = stp_entry.get("ip") or stp_entry.get("target_ip")
                if ip_cand:
                    ttl_val = ttl_data.get(ip_cand)
            if ttl_val is not None:
                if isinstance(ttl_val, dict):
                    ttl_val = ttl_val.get("hop_count", ttl_val.get("hops", ttl_val.get("ttl_hop")))
                try:
                    ttl_hop = int(ttl_val)
                except (ValueError, TypeError):
                    pass

        # Construct node attributes
        effective_ttl_hops = ttl_hop if (ttl_hop is not None and ttl_hop > 0) else 1
        node_attrs = {
            "type": "Endpoint",
            "node_type": "Endpoint",
            "mac": ep,
            "ttl_hop": ttl_hop,
            "ttl_hops": effective_ttl_hops,
            "root_path_cost": root_path_cost,
        }

        # Attach multicast identity attributes if available
        if isinstance(multicast_data, dict) and ep in multicast_data:
            m_info = multicast_data[ep]
            node_attrs["multicast_identity"] = m_info
            node_attrs["mdns_services"] = m_info.get("mdns_services", [])
            node_attrs["ssdp_headers"] = m_info.get("ssdp_headers", [])
            if isinstance(m_info, dict) and "ui_label" in m_info:
                node_attrs["ui_label"] = m_info["ui_label"]

        # Attach chassis intelligence attributes if available
        if isinstance(chassis_data, dict) and ep in chassis_data:
            c_info = chassis_data[ep]
            node_attrs["chassis_intelligence"] = c_info
            if isinstance(c_info, dict) and "tlvs" in c_info:
                node_attrs["hostname"] = c_info["tlvs"].get("hostname")
                node_attrs["port_id"] = c_info["tlvs"].get("port_id")

        # Attach STP intelligence attributes if available
        if isinstance(stp_data, dict) and ep in stp_data:
            node_attrs["stp_intelligence"] = stp_entry

        # Synthesize concise identity_string & ui_label (mitigates O(N^2) layout thrashing and canvas obliteration)
        cand_id = None
        if node_attrs.get("ui_label"):
            cand_id = node_attrs["ui_label"]
        elif node_attrs.get("hostname"):
            cand_id = node_attrs["hostname"]
        elif node_attrs.get("mdns_services") and len(node_attrs["mdns_services"]) > 0:
            cand_id = node_attrs["mdns_services"][0]
        elif node_attrs.get("ssdp_headers") and len(node_attrs["ssdp_headers"]) > 0:
            cand_id = node_attrs["ssdp_headers"][0]
        else:
            cand_id = ep

        clean_id = re.sub(r"[\r\n\t\s]+", " ", str(cand_id)).strip()
        if len(clean_id) > 32:
            clean_id = clean_id[:29] + "..."
        node_attrs["identity_string"] = clean_id
        node_attrs.setdefault("ui_label", clean_id)

        self.graph.add_node(ep, **node_attrs)

        # Establish initial baseline edge to core switch with absolute path cost weighting
        edge_weight = float(root_path_cost) if root_path_cost is not None else 19.0
        self.graph.add_edge(
            core_switch,
            ep,
            weight=edge_weight,
            cost=int(edge_weight),
            root_path_cost=int(edge_weight),
        )

        endpoint_metadata.append({
            "id": ep,
            "ttl_hop": ttl_hop,
            "root_path_cost": root_path_cost,
        })

    # 3. Gap-Filling Algorithm: Cluster endpoints by (ttl_hop, root_path_cost)
    grouping = {}
    for ep_data in endpoint_metadata:
        h = ep_data["ttl_hop"]
        c = ep_data["root_path_cost"]
        if h is not None and c is not None:
            key = (h, c)
            if key not in grouping:
                grouping[key] = []
            grouping[key].append(ep_data["id"])

    # 4. Inject Unmanaged_Switch at convergence points
    switch_counter = 1
    for (h, c), members in grouping.items():
        if len(members) > 1:
            # Compliance enforcement: Prevent hallucination by calculating and clamping
            # standard deviation of broadcast propagation delays prior to node injection
            delays = []
            for m in members:
                m_info = multicast_data.get(m, {}) if isinstance(multicast_data, dict) else {}
                s_info = stp_data.get(m, {}) if isinstance(stp_data, dict) else {}
                c_info = chassis_data.get(m, {}) if isinstance(chassis_data, dict) else {}
                delay_candidates = (
                    m_info.get("propagation_delay"),
                    m_info.get("delay"),
                    m_info.get("rtt"),
                    s_info.get("propagation_delay"),
                    s_info.get("delay"),
                    s_info.get("rtt"),
                    c_info.get("propagation_delay"),
                    c_info.get("delay"),
                    c_info.get("rtt"),
                )
                d = next((candidate for candidate in delay_candidates if candidate is not None), None)
                if d is not None:
                    try:
                        delays.append(float(d))
                    except (ValueError, TypeError):
                        pass

            if len(delays) > 1:
                mean_delay = sum(delays) / len(delays)
                var_delay = sum((d - mean_delay) ** 2 for d in delays) / len(delays)
                sigma_delay = math.sqrt(var_delay)
                # Clamped standard deviation baseline
                clamped_sigma = min(sigma_delay, 25.0)
                if sigma_delay > 500.0:
                    # Reject injection if delay variance indicates divergent broadcast domains
                    continue

            # Project unmanaged switch node identifier
            inferred_switch = "Unmanaged_Switch" if switch_counter == 1 else f"Unmanaged_Switch_{switch_counter}"
            switch_counter += 1

            self.graph.add_node(
                inferred_switch,
                type="Unmanaged_Switch",
                node_type="Unmanaged_Switch",
                label="Unmanaged_Switch",
                ttl_hop=h,
                ttl_hops=h,
                pathcost=c,
                root_path_cost=c,
            )

            # Connect inferred switch to core switch with absolute path cost weighting
            self.graph.add_edge(
                core_switch,
                inferred_switch,
                weight=float(c),
                cost=int(c),
                root_path_cost=int(c),
            )

            # Redraw edges: remove core switch direct links and attach endpoints to the unmanaged switch hub
            for member in members:
                if self.graph.has_edge(core_switch, member):
                    self.graph.remove_edge(core_switch, member)

                self.graph.add_edge(
                    inferred_switch,
                    member,
                    weight=1.0,
                    cost=int(c),
                    root_path_cost=int(c),
                )

    return self.graph


class TopologyProjectionEngine(TopologyProjectionPort):
    """Compatibility wrapper exposing the topology projection port."""

    def __init__(
        self,
        fused_matrix: Optional[Dict[str, Any]] = None,
        chassis_matrix: Optional[Dict[str, Any]] = None,
        stp_matrix: Optional[Dict[str, Any]] = None,
        ttl_matrix: Optional[Dict[str, Any]] = None,
        multicast_matrix: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.fused_matrix = fused_matrix or {}
        self.chassis_matrix = chassis_matrix or {}
        self.stp_matrix = stp_matrix or {}
        self.ttl_matrix = ttl_matrix or {}
        self.multicast_matrix = multicast_matrix or {}
        self.graph = nx.DiGraph()

    def project_topology(
        self, fused_matrix: Optional[Dict[str, Any]] = None
    ) -> nx.DiGraph:
        if fused_matrix is not None:
            self.fused_matrix = fused_matrix
        return project_topology(self, fused_matrix)