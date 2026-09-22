"""
Project AETHERIS - Topology Graph Store
Maintains nodes, physical link edges, and spatial distance state estimates.
"""

from typing import Dict, Any, List, Optional
import json
import networkx as nx


class GraphStore:
    def __init__(self):
        self._graph = nx.DiGraph()

    @property
    def nodes(self) -> Dict[str, Dict[str, Any]]:
        """Dictionary access property for all nodes."""
        return {n: dict(data) for n, data in self._graph.nodes(data=True)}

    @property
    def edges(self) -> List[Dict[str, Any]]:
        """List access property for all edges."""
        return self.get_all_edges()

    def upsert_node(self, node_id: str, properties: Optional[Dict[str, Any]] = None) -> None:
        """Upserts a topological node (switch, endpoint, gateway, peripheral)."""
        props = properties or {}
        if self._graph.has_node(node_id):
            self._graph.nodes[node_id].update(props)
        else:
            self._graph.add_node(node_id, **props)

    def add_node(self, node_id: str, properties: Optional[Dict[str, Any]] = None) -> None:
        """Backward-compatible alias for upsert_node."""
        self.upsert_node(node_id, properties)

    @classmethod
    def close_all(cls) -> None:
        """Teardown hook for test cleanup compatibility."""
        pass

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str = "ETHERNET_LINK",
        distance_m: Optional[float] = None,
        variance_m2: Optional[float] = None,
        confidence_pct: float = 0.0,
        is_anchor: bool = False,
        **extra_attrs
    ) -> None:
        """Upserts a directed physical link with spatial uncertainty metrics."""
        attrs = {
            "type": edge_type,
            "edge_type": edge_type,
            "distance_m": distance_m,
            "variance_m2": variance_m2,
            "confidence_pct": confidence_pct,
            "is_anchor": is_anchor,
            **extra_attrs
        }
        self._graph.add_edge(source, target, **attrs)

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves raw node properties if the node exists."""
        if self._graph.has_node(node_id):
            return dict(self._graph.nodes[node_id])
        return None

    def get_edge(self, source: str, target: str) -> Optional[Dict[str, Any]]:
        """Retrieves link properties between two nodes if the edge exists."""
        if self._graph.has_edge(source, target):
            return dict(self._graph.edges[source, target])
        return None

    def get_all_nodes(self) -> Dict[str, Dict[str, Any]]:
        """Returns a copy of all nodes and their property mappings."""
        return self.nodes

    def get_all_edges(self) -> List[Dict[str, Any]]:
        """Returns all edges formatted as an adjacency list."""
        edges = []
        for u, v, data in self._graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                **data
            })
        return edges

    def get_neighbors(self, node_id: str) -> List[str]:
        """Returns immediate outbound adjacent neighbors for a given node."""
        if self._graph.has_node(node_id):
            return list(self._graph.successors(node_id))
        return []

    def get_cytoscape_elements(self) -> List[Dict[str, Any]]:
        """Serializes the topology graph for Cytoscape WebGL rendering."""
        elements = []
        for node_id, data in self._graph.nodes(data=True):
            confidence = data.get('confidence_pct', data.get('confidence', 50))
            
            # Map discovered attributes to dynamic Cytoscape classes
            arch = str(data.get('archetype', '')).upper()
            dtype = str(data.get('device_type', '')).upper()
            classes = []
            if 'PLC' in arch or 'MODBUS' in arch or 'SCADA' in arch or 'OT' in arch or 'PLC' in dtype:
                classes.append('ics_controller')
            elif 'CAMERA' in arch or 'CCTV' in arch or 'NVR' in arch or 'SURVEILLANCE' in arch or 'ONVIF' in arch:
                classes.append('physical_security')
            elif 'ACCESS_CONTROL' in arch or 'MSP' in arch or 'MERCURY' in arch:
                classes.append('acs_controller')
            else:
                classes.append('it_device')
                
            elements.append({
                "data": {
                    "id": node_id,
                    "label": data.get("hostname", data.get("label", node_id)),
                    "confidence": confidence,
                    **data
                },
                "classes": " ".join(classes)
            })
        for u, v, data in self._graph.edges(data=True):
            edge_classes = []
            
            # Map edge_type to visual constraints
            etype = str(data.get('edge_type', '')).upper()
            if 'WIRELESS' in etype or 'WLAN' in etype:
                edge_classes.append('link_wireless')
            elif 'FIBER' in etype:
                edge_classes.append('link_fiber')
            else:
                edge_classes.append('link_utp')

            if data.get('distance_m') is not None and data.get('distance_m', 0) > 0:
                edge_classes.append('thermodynamic_link')
                data['z_axis_label'] = f"{data['distance_m']:.1f} meters"
            
            elements.append({
                "data": {
                    "id": f"{u}->{v}",
                    "source": u,
                    "target": v,
                    **data
                },
                "classes": " ".join(edge_classes)
            })
        return elements

    def export_cytoscape_elements(self) -> List[Dict[str, Any]]:
        """Backward-compatible alias for get_cytoscape_elements."""
        return self.get_cytoscape_elements()

    def to_json(self) -> str:
        """Exports graph state to serialized JSON string."""
        return json.dumps(nx.node_link_data(self._graph))

    def from_json(self, json_str: str) -> None:
        """Restores graph state from serialized JSON string."""
        data = json.loads(json_str)
        self._graph = nx.node_link_graph(data)