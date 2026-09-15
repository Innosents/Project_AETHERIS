import networkx as nx
from typing import Dict, Any, List, Optional, Tuple, Union


class MultiHopRiserSolver:
    """
    Computes cumulative infrastructure propagation latency across switch trunks
    and distribution risers to isolate final-hop edge cable lengths.
    """
    DEFAULT_ASIC_FORWARDING_LATENCY_US = 1.2  # Nominal store-and-forward latency
    C_COPPER_NVP = 0.69
    C_FIBER_NVP = 0.67
    C_VACUUM = 299792458.0

    @classmethod
    def calculate_path_overhead(
        cls,
        graph: Any,
        root_switch_id: str,
        target_switch_id: str
    ) -> Tuple[float, float, List[str]]:
        """
        Traverses shortest trunk path from root prober switch to target access switch.
        Returns: (total_overhead_us, total_distance_m, path_hops)
        """
        if root_switch_id == target_switch_id or not target_switch_id:
            return 0.0, 0.0, [root_switch_id]

        g = graph._graph if hasattr(graph, "_graph") else graph

        try:
            path = nx.shortest_path(g, source=root_switch_id, target=target_switch_id)
        except nx.NetworkXNoPath:
            try:
                path = nx.shortest_path(g.to_undirected(), source=root_switch_id, target=target_switch_id)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return 0.0, 0.0, [root_switch_id]
        except (nx.NodeNotFound, Exception):
            return 0.0, 0.0, [root_switch_id]

        total_latency_us = 0.0
        total_distance_m = 0.0

        for u, v in zip(path[:-1], path[1:]):
            edge_data = g.get_edge_data(u, v, default={})
            if not edge_data and hasattr(g, "is_directed") and g.is_directed():
                edge_data = g.get_edge_data(v, u, default={})
            
            # 1. Physical propagation flight time along the riser
            dist_m = float(edge_data.get("distance_m", 0.0))
            media = edge_data.get("media_type", "COPPER_CAT6A")
            nvp = cls.C_FIBER_NVP if "FIBER" in media else cls.C_COPPER_NVP
            v_prop = nvp * cls.C_VACUUM
            
            flight_time_us = ((2.0 * dist_m) / v_prop) * 1e6
            
            # 2. Intermediate switch ASIC forwarding latency
            asic_us = float(edge_data.get("asic_latency_us", cls.DEFAULT_ASIC_FORWARDING_LATENCY_US))

            total_latency_us += (flight_time_us + asic_us)
            total_distance_m += dist_m

        return round(total_latency_us, 3), round(total_distance_m, 2), path

