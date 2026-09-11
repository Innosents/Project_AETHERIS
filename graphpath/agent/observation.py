"""
GraphPath Native Orchestration Agent - Formal Observation Space
Sprint 1: State observation tensor encoding, subnet host projection,
OT risk indexing, spatial error calculation, and socket headroom tracking.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Union
import numpy as np

# Canonical 37 common listening ports with O(1) constant lookup, including EtherNet/IP CIP (44818)
CANONICAL_37_PORTS: List[int] = [
    22, 53, 80, 102, 111, 135, 139, 161, 443, 445, 502, 515, 554, 631,
    1900, 2049, 3000, 3001, 3306, 3389, 5060, 5061, 5353, 5432, 5985,
    5986, 8000, 8001, 8002, 8060, 8080, 8088, 8443, 9100, 23001, 37777, 44818
]
AGENT_COMMON_PORTS: List[int] = CANONICAL_37_PORTS
PORT_TO_INDEX: Dict[int, int] = {port: idx for idx, port in enumerate(AGENT_COMMON_PORTS)}

# Recognized Industrial OT / Physical Infrastructure archetypes
CRITICAL_OT_TYPES = {"plc", "pac", "access_control", "mercury", "pacs", "rtu"}
INTERMEDIATE_OT_TYPES = {"hmi", "scada", "sensor_hub", "switch", "industrial_switch"}
SURVEILLANCE_TYPES = {"camera", "nvr"}


@dataclass
class AgentObservation:
    """
    Formal structured observation dataclass representing the cyber-physical state
    of a target industrial subnet.
    """
    occupancy_bitmap: np.ndarray          # Shape (256,), dtype float32
    port_matrix: np.ndarray               # Shape (256, 37), dtype float32
    ot_risk_index: float                  # Bounded in [0.0, 1.0]
    spatial_error_mean: float             # Mean error radius in meters (>= 0.0)
    socket_budget_remaining: int          # Remaining socket pool headroom (>= 0)
    spatial_error_mean_m: float = 0.0     # Explicit raw diagnostic metric alias
    target_subnet: str = ""
    spatial_variance: Dict[str, float] = field(default_factory=dict)
    spatial_confidence_radius: Dict[str, float] = field(default_factory=dict)
    h1_persistent_entropy: float = 0.0    # 1D persistent entropy in [0.0, 1.0]
    h1_max_cycle_persistence: float = 0.0 # Maximum 1D cycle lifetime in [0.0, 1.0]

    def __post_init__(self):
        if not self.spatial_error_mean_m and self.spatial_error_mean:
            self.spatial_error_mean_m = self.spatial_error_mean
        elif not self.spatial_error_mean and self.spatial_error_mean_m:
            self.spatial_error_mean = self.spatial_error_mean_m

        # Guarantee shape and dtype invariants
        if self.occupancy_bitmap.shape != (256,):
            raise ValueError(f"occupancy_bitmap shape must be (256,), got {self.occupancy_bitmap.shape}")
        if self.port_matrix.shape != (256, 37):
            raise ValueError(f"port_matrix shape must be (256, 37), got {self.port_matrix.shape}")

    def to_tensor(self, include_topological: bool = False) -> Any:
        """
        Returns a 1D PyTorch-compatible float32 array:
        - If include_topological is False (default): shape (9731,) for backward compatibility.
        - If include_topological is True: shape (9733,) incorporating higher-order topological features.
        If PyTorch is installed, wraps zero-copy via torch.from_numpy().
        Otherwise, returns a contiguous np.ndarray (dtype=np.float32).
        """
        norm_spatial = float(np.tanh(max(0.0, self.spatial_error_mean) / 100.0))
        norm_socket = float(np.tanh(max(0.0, float(self.socket_budget_remaining)) / 10.0))
        bounded_ot_risk = float(np.clip(self.ot_risk_index, 0.0, 1.0))

        if include_topological:
            scalars = np.array([
                bounded_ot_risk,
                norm_spatial,
                norm_socket,
                float(np.clip(self.h1_persistent_entropy, 0.0, 1.0)),
                float(np.clip(self.h1_max_cycle_persistence, 0.0, 1.0)),
            ], dtype=np.float32)
        else:
            scalars = np.array([
                bounded_ot_risk,
                norm_spatial,
                norm_socket,
            ], dtype=np.float32)

        flat = np.concatenate([
            self.occupancy_bitmap.astype(np.float32),          # 256
            self.port_matrix.flatten().astype(np.float32),     # 256 * 37 = 9472
            scalars,
        ], dtype=np.float32)

        # Guard against NaNs or Infs
        flat = np.nan_to_num(flat, nan=0.0, posinf=1.0, neginf=0.0)

        try:
            import torch
            return torch.from_numpy(flat)
        except ImportError:
            return flat

    def to_topological_tensor(self) -> Any:
        """Returns the higher-order 9,733-dimensional topological observation tensor."""
        return self.to_tensor(include_topological=True)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes observation metadata for telemetry and debugging."""
        return {
            "target_subnet": self.target_subnet,
            "active_hosts_count": int(np.sum(self.occupancy_bitmap)),
            "open_ports_count": int(np.sum(self.port_matrix)),
            "ot_risk_index": round(self.ot_risk_index, 4),
            "spatial_error_mean_m": round(self.spatial_error_mean, 2),
            "socket_budget_remaining": self.socket_budget_remaining,
            "spatial_variance": self.spatial_variance,
            "spatial_confidence_radius": self.spatial_confidence_radius,
            "h1_persistent_entropy": round(self.h1_persistent_entropy, 4),
            "h1_max_cycle_persistence": round(self.h1_max_cycle_persistence, 4),
            "tensor_dimension": 256 + (256 * 37) + 3,
        }

    def is_port_active(self, target_ip: str, port: int) -> bool:
        """
        Safely checks if a specific port is marked active (1.0) in port_matrix for target_ip.
        Returns False if target_ip cannot be parsed, does not belong to target_subnet,
        or if port is not active/tracked.
        """
        if not target_ip or not self.target_subnet:
            return False
        
        try:
            net = ipaddress.ip_network(self.target_subnet, strict=False)
            ip_obj = ipaddress.ip_address(str(target_ip).split(":")[0].strip())
        except (ValueError, TypeError, AttributeError):
            return False

        if ip_obj not in net:
            return False

        base_ip_int = int(net.network_address)
        raw_offset = int(ip_obj) - base_ip_int
        if 0 <= raw_offset < 256:
            host_idx = raw_offset
        else:
            host_idx = raw_offset % 256

        port_idx = PORT_TO_INDEX.get(port)
        if port_idx is None:
            return False

        try:
            return bool(self.port_matrix[host_idx, port_idx] > 0.5)
        except (IndexError, TypeError):
            return False


class AgentObservationEncoder:
    """
    Transforms live GraphStore topologies, target subnet CIDR boundaries,
    and SafetyMonitor metrics into a mathematical observation space.
    """

    @classmethod
    def encode(
        cls,
        graph_store: Any,
        target_subnet: str,
        safety_metrics: Optional[Dict[str, Any]] = None
    ) -> AgentObservation:
        """
        Encodes the cyber-physical state of target_subnet from graph_store.
        
        Args:
            graph_store: GraphStore instance containing current topology nodes.
            target_subnet: Subnet CIDR string (e.g., '10.10.30.0/24' or '172.21.144.0/20').
            safety_metrics: Optional metrics snapshot from SafetyMonitor.
        """
        occupancy_bitmap = np.zeros(256, dtype=np.float32)
        port_matrix = np.zeros((256, 37), dtype=np.float32)
        safety_metrics = safety_metrics or {}

        try:
            net = ipaddress.ip_network(target_subnet, strict=False)
        except ValueError:
            # Fallback to a zero observation if invalid CIDR is passed
            return AgentObservation(
                occupancy_bitmap=occupancy_bitmap,
                port_matrix=port_matrix,
                ot_risk_index=0.0,
                spatial_error_mean=0.0,
                socket_budget_remaining=cls._calculate_socket_headroom(safety_metrics),
                target_subnet=target_subnet,
            )

        base_ip_int = int(net.network_address)
        nodes = graph_store.nodes if hasattr(graph_store, "nodes") else {}

        subnet_nodes: List[Dict[str, Any]] = []
        spatial_errors: List[float] = []
        spatial_variance: Dict[str, float] = {}
        spatial_confidence_radius: Dict[str, float] = {}

        for node_id, node_data in nodes.items():
            ip_str = str(node_data.get("ip") or node_id).split(":")[0].strip()
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            if ip_obj in net:
                subnet_nodes.append(node_data)
                
                # --- Correction 1: /24 Subnet Offset Indexing Edge Case ---
                raw_offset = int(ip_obj) - base_ip_int
                if 0 <= raw_offset < 256:
                    host_idx = raw_offset
                else:
                    # If prefixlen < 24, slice host offset into a canonical 256-slot representation
                    host_idx = raw_offset % 256

                occupancy_bitmap[host_idx] = 1.0

                # --- Correction 4: O(1) Port Mapping ---
                open_ports = node_data.get("open_ports") or []
                if not open_ports and "metadata" in node_data and isinstance(node_data["metadata"], dict):
                    open_ports = node_data["metadata"].get("open_ports", [])

                for p in open_ports:
                    try:
                        p_int = int(p)
                    except (ValueError, TypeError):
                        continue
                    p_idx = PORT_TO_INDEX.get(p_int)
                    if p_idx is not None:
                        port_matrix[host_idx, p_idx] = 1.0

                # --- Spatial Uncertainty & Error Metric Extraction ---
                sm = node_data.get("spatial_metrics") or {}
                if not sm and "metadata" in node_data and isinstance(node_data["metadata"], dict):
                    sm = node_data["metadata"].get("spatial_metrics") or {}

                # Variance extraction (P in m^2)
                var_val = sm.get("variance") or sm.get("variance_m2") or sm.get("P")
                if var_val is not None:
                    spatial_variance[ip_str] = float(var_val)

                # Confidence radius extraction (r_95 in meters)
                err_radius = (
                    sm.get("confidence_radius_95")
                    or sm.get("confidence_radius")
                    or sm.get("error_radius_meters")
                    or sm.get("error_radius")
                )
                if err_radius is not None:
                    err_radius_f = float(err_radius)
                    spatial_confidence_radius[ip_str] = err_radius_f
                    spatial_errors.append(err_radius_f)
                    if ip_str not in spatial_variance:
                        spatial_variance[ip_str] = float((err_radius_f / 1.96) ** 2)
                elif "confidence" in sm:
                    conf = float(sm["confidence"])
                    inferred_err = max(0.5, (1.0 - conf) * 30.0)
                    spatial_confidence_radius[ip_str] = inferred_err
                    spatial_errors.append(inferred_err)
                    if ip_str not in spatial_variance:
                        spatial_variance[ip_str] = float((inferred_err / 1.96) ** 2)
                elif "distance_meters" in sm:
                    spatial_errors.append(15.0)
                    spatial_confidence_radius[ip_str] = 15.0
                    if ip_str not in spatial_variance:
                        spatial_variance[ip_str] = float((15.0 / 1.96) ** 2)

        # --- Correction 3: Spatial Error Mean ---
        if spatial_errors:
            spatial_error_mean = float(np.mean(spatial_errors))
        else:
            spatial_error_mean = 0.0

        # --- OT Risk Index Calculation ---
        ot_risk_index = cls._calculate_ot_risk_index(subnet_nodes)

        # --- Socket Budget Headroom ---
        socket_budget_remaining = cls._calculate_socket_headroom(safety_metrics)

        # --- Vietoris-Rips Persistent Homology Features ---
        try:
            from src.graphpath.agent.topological_complex import VietorisRipsHomology
            h1_entropy, h1_max_pers = VietorisRipsHomology.extract_features_from_subnet(
                graph_store=graph_store,
                target_subnet=target_subnet,
            )
        except Exception:
            h1_entropy, h1_max_pers = 0.0, 0.0

        return AgentObservation(
            occupancy_bitmap=occupancy_bitmap,
            port_matrix=port_matrix,
            ot_risk_index=ot_risk_index,
            spatial_error_mean=spatial_error_mean,
            socket_budget_remaining=socket_budget_remaining,
            spatial_error_mean_m=spatial_error_mean,
            target_subnet=target_subnet,
            spatial_variance=spatial_variance,
            spatial_confidence_radius=spatial_confidence_radius,
            h1_persistent_entropy=h1_entropy,
            h1_max_cycle_persistence=h1_max_pers,
        )

    @staticmethod
    def _calculate_ot_risk_index(nodes: List[Dict[str, Any]]) -> float:
        """
        Derives an operational risk index in [0.0, 1.0] from detected device types
        and industrial OT archetypes in the target subnet.
        """
        if not nodes:
            return 0.0

        total_weight = 0.0
        critical_count = 0

        for n in nodes:
            dtype = str(n.get("type", "")).lower()
            vendor = str(n.get("vendor", "")).lower()

            if dtype in CRITICAL_OT_TYPES or any(v in vendor for v in ("schneider", "rockwell", "siemens", "mercury")):
                total_weight += 1.0
                critical_count += 1
            elif dtype in INTERMEDIATE_OT_TYPES or "moxa" in vendor:
                total_weight += 0.7
            elif dtype in SURVEILLANCE_TYPES or any(v in vendor for v in ("axis", "tiandy", "hikvision")):
                total_weight += 0.3
            else:
                total_weight += 0.05

        # Normalize across discovered nodes with a boost for critical controllers
        base_ratio = total_weight / float(len(nodes))
        critical_boost = 0.25 if critical_count > 0 else 0.0
        return float(np.clip(base_ratio + critical_boost, 0.0, 1.0))

    @staticmethod
    def _calculate_socket_headroom(safety_metrics: Dict[str, Any]) -> int:
        """Calculates live socket headroom before hitting SafetyMonitor ceilings."""
        if not safety_metrics:
            return 4  # Nominal default headroom

        if "socket_budget_remaining" in safety_metrics:
            return max(0, int(safety_metrics["socket_budget_remaining"]))

        ceiling = int(safety_metrics.get("max_socket_ceiling", 4))
        active = safety_metrics.get("active_connections", {})
        if isinstance(active, dict):
            current_active = sum(active.values())
        else:
            current_active = int(active)

        return max(0, ceiling - current_active)
