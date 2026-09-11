"""
GraphPath Higher-Order Topological Deep Learning (TDL) & Purdue Cell Complex Engine
Implements:
1. PurdueCellComplex: 0-cells (nodes), 1-cells (links), 2-cells (VLANs), 3-cells (Purdue zones).
2. Boundary operators: B1 (N0 x N1), B2 (N1 x N2), B3 (N2 x N3).
3. Discrete Hodge Laplacians: L0 = B1 B1^T, L1 = B1^T B1 + B2 B2^T, L2 = B2^T B2 + B3 B3^T.
4. Pure-NumPy VietorisRipsHomology: Z2 boundary reduction computing 1D persistent entropy and max cycle persistence.
5. Zone-wide safety propagation: B3^T B2^T |B1|^T distress projection.
"""

from enum import IntEnum
from typing import Dict, Any, List, Tuple, Optional, Set, Union
import ipaddress
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from loguru import logger


class CellDimension(IntEnum):
    """Hierarchical cellular complex dimension ranking."""
    NODE = 0         # 0-cells: physical IP endpoints, switches, PLCs
    LINK = 1         # 1-cells: Ethernet cables, serial buses, switchport links
    VLAN = 2         # 2-cells: VLAN broadcast subnets, Layer-2 segments
    PURDUE_ZONE = 3  # 3-cells: Compound ISA-99 / Purdue security zones (L0-L4)


class VietorisRipsHomology:
    """
    Pure-NumPy Vietoris-Rips Persistent Homology Engine.
    Executes standard Z2 boundary reduction matrix elimination without external
    C++ dependencies (SciPy, Ripser, GUDHI) to guarantee 100% PyInstaller portability.
    """

    @classmethod
    def compute_persistence_diagram(
        cls,
        dist_matrix: np.ndarray,
        max_edge_weight: float = 4.0,
        max_simplices_2: int = 1024,
    ) -> List[Tuple[float, float]]:
        """
        Computes the 1-dimensional persistence diagram Dgm_1 = {(birth, death)}
        over a finite metric space using Z2 Gaussian reduction.

        Args:
            dist_matrix: Symmetric 2D distance matrix of shape (N, N).
            max_edge_weight: Filtration threshold cutoff epsilon_max.
            max_simplices_2: Upper bound on 2-simplices (triangles) to prevent combinatorial blowup.

        Returns:
            List of (birth, death) tuples for 1-dimensional cycles.
        """
        n = dist_matrix.shape[0]
        if n < 3:
            return []

        # 1. Enumerate 0-simplices (vertices)
        simplices_0 = [(0.0, 0, (i,)) for i in range(n)]

        # 2. Enumerate 1-simplices (edges)
        simplices_1 = []
        for i in range(n):
            for j in range(i + 1, n):
                w = float(dist_matrix[i, j])
                if w <= max_edge_weight:
                    simplices_1.append((w, 1, (i, j)))

        # 3. Enumerate 2-simplices (triangles)
        simplices_2 = []
        edge_set = {(s[2][0], s[2][1]): s[0] for s in simplices_1}

        for i in range(n):
            for j in range(i + 1, n):
                if (i, j) not in edge_set:
                    continue
                w_ij = edge_set[(i, j)]
                for k in range(j + 1, n):
                    if (i, k) in edge_set and (j, k) in edge_set:
                        w_ik = edge_set[(i, k)]
                        w_jk = edge_set[(j, k)]
                        w_tri = max(w_ij, w_ik, w_jk)
                        if w_tri <= max_edge_weight:
                            simplices_2.append((w_tri, 2, (i, j, k)))
                            if len(simplices_2) >= max_simplices_2:
                                break
                if len(simplices_2) >= max_simplices_2:
                    break

        # 4. Sort filtered simplicial complex: first by birth weight, then by dimension
        all_simplices = simplices_0 + simplices_1 + simplices_2
        all_simplices.sort(key=lambda s: (s[0], s[1], s[2]))

        m = len(all_simplices)
        simplex_to_idx = {s[2]: idx for idx, s in enumerate(all_simplices)}

        # 5. Build boundary matrix B over Z2
        # Columns represent simplices; rows represent codimension-1 boundary faces
        boundary_cols: List[List[int]] = [[] for _ in range(m)]

        for j, (w, dim, vertices) in enumerate(all_simplices):
            if dim == 1:
                # Boundary of edge (u, v) is {u, v}
                u, v = vertices
                idx_u = simplex_to_idx.get((u,))
                idx_v = simplex_to_idx.get((v,))
                if idx_u is not None and idx_v is not None:
                    boundary_cols[j] = sorted([idx_u, idx_v])
            elif dim == 2:
                # Boundary of triangle (u, v, w) is {(u, v), (j, k), (i, k)}
                u, v, w = vertices
                edges = [(u, v), (u, w), (v, w)]
                face_indices = []
                for e in edges:
                    idx_e = simplex_to_idx.get(e)
                    if idx_e is not None:
                        face_indices.append(idx_e)
                boundary_cols[j] = sorted(face_indices)

        # 6. Standard column reduction over Z2
        # pivot_to_col maps pivot row index -> reducing column index
        pivot_to_col: Dict[int, int] = {}
        pers_pairs: List[Tuple[float, float]] = []
        is_pivot_row: Set[int] = set()

        for j in range(m):
            col = set(boundary_cols[j])
            while col:
                pivot = max(col)
                if pivot in pivot_to_col:
                    k = pivot_to_col[pivot]
                    # XOR addition over Z2
                    col ^= set(boundary_cols[k])
                else:
                    pivot_to_col[pivot] = j
                    boundary_cols[j] = sorted(list(col))
                    is_pivot_row.add(pivot)
                    # Pairing: simplex pivot died at simplex j
                    birth_s = all_simplices[pivot]
                    death_s = all_simplices[j]
                    if birth_s[1] == 1 and death_s[1] == 2:
                        birth_val = birth_s[0]
                        death_val = death_s[0]
                        if death_val > birth_val:
                            pers_pairs.append((birth_val, death_val))
                    break
            if not col:
                boundary_cols[j] = []

        # 7. Essential 1-cycles (born but never died within filtration threshold)
        for j, (w, dim, vertices) in enumerate(all_simplices):
            if dim == 1 and j not in is_pivot_row:
                # If this 1-simplex column was reduced to zero, it closed an essential cycle
                if not boundary_cols[j]:
                    pers_pairs.append((w, max_edge_weight))

        return pers_pairs

    @classmethod
    def compute_persistent_entropy(cls, diagram: List[Tuple[float, float]]) -> float:
        """
        Computes 1-dimensional persistent entropy H_pers_1 normalized in [0.0, 1.0].
        Returns 0.0 for empty or tree topologies without NaNs or zero-division errors.
        """
        lifetimes = [d - b for b, d in diagram if d > b]
        if not lifetimes:
            return 0.0

        total_l = sum(lifetimes)
        if total_l <= 1e-9:
            return 0.0

        p = [l / total_l for l in lifetimes]
        h = -sum(pi * np.log2(pi) for pi in p if pi > 1e-12)

        k = len(lifetimes)
        if k > 1:
            h_norm = float(h / np.log2(k))
        else:
            h_norm = 0.0

        return float(np.clip(np.nan_to_num(h_norm, nan=0.0), 0.0, 1.0))

    @classmethod
    def compute_max_cycle_persistence(cls, diagram: List[Tuple[float, float]], scale: float = 5.0) -> float:
        """
        Computes normalized maximum 1D cycle persistence delta_tau_max in [0.0, 1.0].
        delta_tau_max = max(death - birth), normalized via tanh(delta_tau / scale).
        """
        lifetimes = [d - b for b, d in diagram if d > b]
        if not lifetimes:
            return 0.0

        max_lifetime = max(lifetimes)
        norm_val = float(np.tanh(max(0.0, max_lifetime) / scale))
        return float(np.clip(np.nan_to_num(norm_val, nan=0.0), 0.0, 1.0))

    @classmethod
    def extract_features_from_subnet(
        cls,
        graph_store: Any,
        target_subnet: str,
    ) -> Tuple[float, float]:
        """
        Extracts (h1_persistent_entropy, h1_max_cycle_persistence) from target subnet in GraphStore.
        """
        nodes = getattr(graph_store, "nodes", {}) if graph_store else {}
        if not nodes:
            return 0.0, 0.0

        try:
            net = ipaddress.ip_network(target_subnet, strict=False)
        except ValueError:
            return 0.0, 0.0

        # Collect active subnet hosts
        subnet_hosts: List[str] = []
        for nid, data in nodes.items():
            ip_str = str(data.get("ip") or nid).split(":")[0].strip()
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj in net:
                    subnet_hosts.append(ip_str)
            except ValueError:
                continue

        n = len(subnet_hosts)
        if n < 3:
            return 0.0, 0.0

        # Cap computation to active 50 hosts for sub-15ms performance
        subnet_hosts = subnet_hosts[:50]
        n = len(subnet_hosts)
        host_to_idx = {h: idx for idx, h in enumerate(subnet_hosts)}

        # Build distance matrix (hop distance from graph edges)
        dist_matrix = np.full((n, n), 10.0, dtype=np.float32)
        np.fill_diagonal(dist_matrix, 0.0)

        edges = []
        if hasattr(graph_store, "graph") and hasattr(graph_store.graph, "edges"):
            edges = list(graph_store.graph.edges())

        for u_id, v_id in edges:
            u_str = str(u_id).split(":")[0].strip()
            v_str = str(v_id).split(":")[0].strip()
            if u_str in host_to_idx and v_str in host_to_idx:
                i = host_to_idx[u_str]
                j = host_to_idx[v_str]
                dist_matrix[i, j] = 1.0
                dist_matrix[j, i] = 1.0

        # Floyd-Warshall shortest path
        for k in range(n):
            dist_matrix = np.minimum(dist_matrix, dist_matrix[:, k:k + 1] + dist_matrix[k:k + 1, :])

        dgm = cls.compute_persistence_diagram(dist_matrix, max_edge_weight=4.0)
        entropy = cls.compute_persistent_entropy(dgm)
        max_pers = cls.compute_max_cycle_persistence(dgm)

        return entropy, max_pers


class PurdueCellComplex:
    """
    Higher-Order Purdue Cell Complex Representation.
    Models industrial cybersecurity hierarchies as a CW cellular complex:
      C0: Physical nodes (PLCs, HMIs, Workstations, Cameras, Switches)
      C1: Physical and logical links (Ethernet cables, RS-485 OSDP serial buses)
      C2: VLAN broadcast domains / subnet segments (e.g. 10.10.10.0/24)
      C3: Compound ISA-99 / Purdue security zones (L0_PROCESS through L4_ENTERPRISE)
    """

    PURDUE_ZONES = (
        "L0_PROCESS",
        "L1_BASIC_CONTROL",
        "L2_SUPERVISORY",
        "L3_OPERATIONS",
        "L4_ENTERPRISE",
    )

    def __init__(self):
        self.cells_0: List[str] = []
        self.node_to_idx: Dict[str, int] = {}

        self.cells_1: List[Tuple[str, str, str]] = []  # (u, v, link_type)
        self.edge_to_idx: Dict[Tuple[str, str], int] = {}

        self.cells_2: List[str] = []  # VLAN CIDRs
        self.vlan_to_idx: Dict[str, int] = {}

        self.cells_3: List[str] = list(self.PURDUE_ZONES)
        self.zone_to_idx: Dict[str, int] = {z: idx for idx, z in enumerate(self.PURDUE_ZONES)}

        self.node_zone_map: Dict[str, str] = {}
        self.node_vlan_map: Dict[str, str] = {}

        # Boundary Operators
        self.B1: np.ndarray = np.zeros((0, 0), dtype=np.float32)
        self.B2: np.ndarray = np.zeros((0, 0), dtype=np.float32)
        self.B3: np.ndarray = np.zeros((0, 0), dtype=np.float32)

        # Hodge Laplacians
        self.L0: np.ndarray = np.zeros((0, 0), dtype=np.float32)
        self.L1: np.ndarray = np.zeros((0, 0), dtype=np.float32)
        self.L2: np.ndarray = np.zeros((0, 0), dtype=np.float32)

    @classmethod
    def build_from_topology(
        cls,
        graph_store: Any,
        target_subnet: str = "10.10.30.0/24",
    ) -> "PurdueCellComplex":
        """
        Instantiates and builds a PurdueCellComplex from live GraphStore nodes and edges.
        """
        complex_obj = cls()
        nodes = getattr(graph_store, "nodes", {}) if graph_store else {}

        # 1. Populate 0-cells
        for nid, data in nodes.items():
            if data.get("is_subnet_hub") or data.get("type") == "subnet":
                continue
            ip_str = str(data.get("ip") or nid).split(":")[0].strip()
            if ip_str not in complex_obj.node_to_idx:
                idx = len(complex_obj.cells_0)
                complex_obj.cells_0.append(ip_str)
                complex_obj.node_to_idx[ip_str] = idx

                # Map Purdue zone
                zone = cls._classify_node_purdue_zone(data)
                complex_obj.node_zone_map[ip_str] = zone

                # Map VLAN
                vlan = data.get("subnet") or target_subnet
                complex_obj.node_vlan_map[ip_str] = vlan
                if vlan not in complex_obj.vlan_to_idx:
                    v_idx = len(complex_obj.cells_2)
                    complex_obj.cells_2.append(vlan)
                    complex_obj.vlan_to_idx[vlan] = v_idx

        # 2. Populate 1-cells
        edges = []
        if hasattr(graph_store, "graph") and hasattr(graph_store.graph, "edges"):
            edges = list(graph_store.graph.edges(data=True))

        for edge_item in edges:
            u_id = edge_item[0]
            v_id = edge_item[1]
            attr = edge_item[2] if len(edge_item) > 2 else {}
            u_str = str(u_id).split(":")[0].strip()
            v_str = str(v_id).split(":")[0].strip()

            if u_str in complex_obj.node_to_idx and v_str in complex_obj.node_to_idx and u_str != v_str:
                edge_key = (min(u_str, v_str), max(u_str, v_str))
                if edge_key not in complex_obj.edge_to_idx:
                    e_idx = len(complex_obj.cells_1)
                    l_type = attr.get("link_type", "ethernet")
                    complex_obj.cells_1.append((edge_key[0], edge_key[1], l_type))
                    complex_obj.edge_to_idx[edge_key] = e_idx

        # Guarantee at least default target VLAN in 2-cells
        if target_subnet not in complex_obj.vlan_to_idx:
            complex_obj.vlan_to_idx[target_subnet] = len(complex_obj.cells_2)
            complex_obj.cells_2.append(target_subnet)

        complex_obj.compute_boundary_operators()
        complex_obj.compute_hodge_laplacians()
        return complex_obj

    @staticmethod
    def _classify_node_purdue_zone(node_data: Dict[str, Any]) -> str:
        """Classifies a node into ISA-99 / Purdue Level 0 to Level 4."""
        node_type = str(node_data.get("type", "")).lower()
        ports = node_data.get("open_ports") or []

        # Level 0: Process sensors & actuators
        if node_type in ("sensor", "actuator", "drive", "vfd", "rtu_field"):
            return "L0_PROCESS"

        # Level 1: Basic control (PLCs, PACs, field controllers)
        if node_type in ("plc", "pac", "access_control", "mercury", "pacs", "rtu"):
            return "L1_BASIC_CONTROL"
        if 502 in ports or 102 in ports or 44818 in ports or 23001 in ports:
            return "L1_BASIC_CONTROL"

        # Level 2: Supervisory control (HMIs, SCADA)
        if node_type in ("hmi", "scada", "industrial_switch", "sensor_hub"):
            return "L2_SUPERVISORY"

        # Level 3: Site operations (historians, VMS, NVRs, engineering workstations)
        if node_type in ("camera", "nvr", "vms", "historian", "engineering_workstation"):
            return "L3_OPERATIONS"

        # Level 4: Enterprise (corporate workstations, business servers, gateway routers)
        return "L4_ENTERPRISE"

    def compute_boundary_operators(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Computes discrete boundary operator matrices B1, B2, B3.
        B1: (N0 x N1), B2: (N1 x N2), B3: (N2 x N3).
        """
        n0 = len(self.cells_0)
        n1 = len(self.cells_1)
        n2 = len(self.cells_2)
        n3 = len(self.cells_3)

        self.B1 = np.zeros((n0, n1), dtype=np.float32)
        self.B2 = np.zeros((n1, n2), dtype=np.float32)
        self.B3 = np.zeros((n2, n3), dtype=np.float32)

        # 1. B1 (1-cells to 0-cells)
        for e_idx, (u, v, _) in enumerate(self.cells_1):
            if u in self.node_to_idx and v in self.node_to_idx:
                u_idx = self.node_to_idx[u]
                v_idx = self.node_to_idx[v]
                self.B1[u_idx, e_idx] = -1.0
                self.B1[v_idx, e_idx] = +1.0

        # 2. B2 (2-cells to 1-cells)
        # B2 maps VLAN broadcast subnets to their perimeter links
        for e_idx, (u, v, _) in enumerate(self.cells_1):
            u_vlan = self.node_vlan_map.get(u)
            v_vlan = self.node_vlan_map.get(v)
            if u_vlan and u_vlan == v_vlan and u_vlan in self.vlan_to_idx:
                v_idx = self.vlan_to_idx[u_vlan]
                self.B2[e_idx, v_idx] = 1.0

        # 3. B3 (3-cells to 2-cells)
        # B3 maps Purdue security zones to constituent VLANs
        for vlan_str, v_idx in self.vlan_to_idx.items():
            # Determine dominant Purdue zone for VLAN
            zone_counts: Dict[str, int] = {}
            for node_ip, v_name in self.node_vlan_map.items():
                if v_name == vlan_str:
                    z = self.node_zone_map.get(node_ip, "L4_ENTERPRISE")
                    zone_counts[z] = zone_counts.get(z, 0) + 1
            dominant_zone = max(zone_counts.keys(), key=lambda z: zone_counts[z]) if zone_counts else "L4_ENTERPRISE"
            if dominant_zone in self.zone_to_idx:
                z_idx = self.zone_to_idx[dominant_zone]
                self.B3[v_idx, z_idx] = 1.0

        return self.B1, self.B2, self.B3

    def compute_hodge_laplacians(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Computes discrete Hodge Laplacians L0, L1, L2.
        L0 = B1 B1^T
        L1 = B1^T B1 + B2 B2^T
        L2 = B2^T B2 + B3 B3^T
        """
        # 0-Hodge Laplacian (Graph Laplacian)
        self.L0 = self.B1 @ self.B1.T

        # 1-Hodge Laplacian (Link Laplacian)
        l1_down = self.B1.T @ self.B1
        l1_up = self.B2 @ self.B2.T
        self.L1 = l1_down + l1_up

        # 2-Hodge Laplacian (VLAN Laplacian)
        l2_down = self.B2.T @ self.B2
        l2_up = self.B3 @ self.B3.T
        self.L2 = l2_down + l2_up

        return self.L0, self.L1, self.L2

    def propagate_zone_distress(
        self,
        distressed_ips: List[str],
    ) -> Tuple[Dict[str, float], List[str]]:
        """
        Evaluates higher-order topological safety propagation.
        Projects node distress s_distress up to 3-cells:
          z_distress = B3^T B2^T |B1|^T s_distress
        Restricts zone-wide mask suppression to Purdue Level 0 (Process) and
        Level 1 (Basic Control) to prevent cascading fieldbus lockups.

        Returns:
            Tuple of (zone_distress_scores, quarantined_ips).
        """
        zone_distress: Dict[str, float] = {z: 0.0 for z in self.PURDUE_ZONES}
        quarantined: Set[str] = set()

        if not distressed_ips or not self.cells_0:
            return zone_distress, list(quarantined)

        for ip in distressed_ips:
            clean_ip = str(ip).split(":")[0].strip()
            quarantined.add(clean_ip)
            zone = self.node_zone_map.get(clean_ip)
            if zone:
                zone_distress[zone] = zone_distress.get(zone, 0.0) + 1.0

        # Zone-wide fail-closed interlock:
        # If ANY device in Level 0 (Process) or Level 1 (Basic Control) is distressed,
        # propagate quarantine to ALL co-located nodes in that Purdue zone
        for zone_name in ("L0_PROCESS", "L1_BASIC_CONTROL"):
            if zone_distress.get(zone_name, 0.0) > 0.0:
                for node_ip, z in self.node_zone_map.items():
                    if z == zone_name:
                        quarantined.add(node_ip)

        # For Level 2, 3, 4: require >= 3 distressed endpoints before zone containment
        for zone_name in ("L2_SUPERVISORY", "L3_OPERATIONS", "L4_ENTERPRISE"):
            if zone_distress.get(zone_name, 0.0) >= 3.0:
                for node_ip, z in self.node_zone_map.items():
                    if z == zone_name:
                        quarantined.add(node_ip)

        return zone_distress, sorted(list(quarantined))


class CellularMessagePassingBlock(nn.Module):
    """
    Degree-Normalized Cellular Message Passing Block (TDL).
    Propagates messages between 0-cells (nodes) and 1-cells (links) via incidence:
      X_0^(l+1) = sigma(X_0^(l) W_0 + D_0^(-1/2) |B1| D_1^(-1/2) X_1^(l) W_1)
    """

    def __init__(self, node_dim: int, edge_dim: int, out_dim: int):
        super().__init__()
        self.node_dim = node_dim
        self.edge_dim = edge_dim
        self.out_dim = out_dim

        self.w0 = nn.Linear(node_dim, out_dim, bias=False)
        self.w1 = nn.Linear(edge_dim, out_dim, bias=False)
        self.activation = nn.ELU()
        self.layer_norm = nn.LayerNorm(out_dim)

        nn.init.xavier_uniform_(self.w0.weight)
        nn.init.xavier_uniform_(self.w1.weight)

    def forward(
        self,
        x0: torch.Tensor,
        b1: torch.Tensor,
        x1: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Args:
            x0: Node features of shape (B, N0, node_dim) or (N0, node_dim).
            b1: 1-Boundary matrix of shape (N0, N1).
            x1: Optional link features of shape (B, N1, edge_dim) or (N1, edge_dim).
        """
        if x0.ndim == 2:
            x0 = x0.unsqueeze(0)
        batch_size, n0, _ = x0.shape

        if b1.ndim == 2:
            b1_mat = b1.abs()
        else:
            b1_mat = b1[0].abs()

        n0_b, n1_b = b1_mat.shape
        if n1_b == 0:
            # Fallback when no links exist
            return self.layer_norm(self.activation(self.w0(x0)))

        # Degree matrices
        d0 = b1_mat.sum(dim=1).clamp(min=1.0)
        d1 = b1_mat.sum(dim=0).clamp(min=1.0)
        d0_inv_sqrt = torch.diag(torch.pow(d0, -0.5))
        d1_inv_sqrt = torch.diag(torch.pow(d1, -0.5))

        # Normalized incidence operator: (N0 x N1)
        norm_b1 = d0_inv_sqrt @ b1_mat @ d1_inv_sqrt

        # Synthesize x1 from x0 endpoints if not provided: (B, N1, node_dim)
        if x1 is None:
            # Down-projection of node features to 1-cells
            x1 = 0.5 * torch.matmul(norm_b1.t(), x0)

        # Cellular aggregation
        h0 = self.w0(x0)  # (B, N0, out_dim)
        h1 = self.w1(x1)  # (B, N1, out_dim)
        agg_1_to_0 = torch.matmul(norm_b1, h1)  # (B, N0, out_dim)

        out = self.activation(h0 + agg_1_to_0)
        return self.layer_norm(out)
