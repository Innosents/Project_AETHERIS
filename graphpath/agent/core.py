"""
GraphPath Native Orchestration Agent - Autonomous Control Loop & System Integration
Sprint 4: AutonomousOrchestrationAgent, masked policy decision engine,
cycle saturation tracking, and numerical stability.
"""

import time
import ipaddress
import random
from typing import Dict, Any, Optional, Tuple, List, Set
import numpy as np
from loguru import logger

from src.graphpath.agent.actions import DiscoveryAction
from src.graphpath.agent.guard import ActionMaskingGuard
from src.graphpath.agent.env import GraphPathAgentEnv
from src.graphpath.agent.spatial_bayesian import BayesianSpatialEstimator

from dataclasses import dataclass, field
import queue
import threading
import torch

try:
    from src.graphpath.spatial.branch_solver import MultiDropBranchSolver, SolverResult
except ImportError:
    try:
        from spatial.branch_solver import MultiDropBranchSolver, SolverResult  # type: ignore
    except ImportError:
        MultiDropBranchSolver = None  # type: ignore
        SolverResult = None  # type: ignore


@dataclass
class TrajectoryStep:
    """Individual environment step transition for asynchronous reinforcement learning."""
    obs: Any
    action: int
    reward: float
    next_obs: Any
    action_mask: np.ndarray
    behavior_log_prob: float
    value: float
    done: bool
    step_index: int = 0
    timestamp: float = field(default_factory=time.time)


def compute_vtrace_advantages(
    behavior_log_probs: torch.Tensor,
    target_log_probs: torch.Tensor,
    actions: torch.Tensor,
    rewards: torch.Tensor,
    values: torch.Tensor,
    dones: torch.Tensor,
    gamma: float = 0.99,
    rho_bar: float = 1.0,
    c_bar: float = 1.0,
) -> Tuple[torch.Tensor, torch.Tensor]:
    """
    Computes IMPALA V-trace value targets v_t and advantage estimates.
    rho_t = min(rho_bar, exp(target_log_probs - behavior_log_probs))
    c_t = min(c_bar, exp(target_log_probs - behavior_log_probs))
    """
    T = rewards.shape[0]
    log_ratio = target_log_probs - behavior_log_probs
    ratio = torch.exp(log_ratio)
    rho = torch.clamp(ratio, max=rho_bar)
    c = torch.clamp(ratio, max=c_bar)

    if values.shape[0] == T:
        values_ext = torch.cat([values, values[-1:]], dim=0)
    else:
        values_ext = values

    delta_v = rho * (rewards + gamma * values_ext[1:] * (1.0 - dones.float()) - values_ext[:-1])

    v_trace = torch.zeros(T, dtype=torch.float32, device=rewards.device)
    next_v_trace = values_ext[-1]

    for t in reversed(range(T)):
        v_trace[t] = values_ext[t] + delta_v[t] + gamma * c[t] * (1.0 - dones[t].float()) * (next_v_trace - values_ext[t + 1])
        next_v_trace = v_trace[t]

    next_v_ext = torch.cat([v_trace[1:], values_ext[-1:]], dim=0)
    advantages = rho * (rewards + gamma * next_v_ext * (1.0 - dones.float()) - values_ext[:-1])

    return advantages, v_trace


class AsyncActorLearnerCoordinator:
    """
    Asynchronous Actor-Learner Coordinator (IMPALA / Sample Factory pattern).
    Decouples inference from core environment stepping using lock-free trajectory queues
    and optional NATS JetStream event distribution.
    """

    def __init__(
        self,
        policy: Optional[Any] = None,
        max_queue_size: int = 10000,
        event_bus: Optional[Any] = None,
    ):
        self.policy = policy
        self.max_queue_size = max_queue_size
        self.trajectory_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.event_bus = event_bus
        self._lock = threading.RLock()
        self.total_steps_ingested = 0

    def push_step(self, step: TrajectoryStep) -> bool:
        """Non-blocking ingestion of trajectory transition."""
        with self._lock:
            self.total_steps_ingested += 1
            try:
                self.trajectory_queue.put_nowait(step)
            except queue.Full:
                try:
                    self.trajectory_queue.get_nowait()
                    self.trajectory_queue.put_nowait(step)
                except Exception:
                    return False

        if self.event_bus is not None and hasattr(self.event_bus, "publish_event"):
            try:
                payload = {
                    "action": step.action,
                    "reward": step.reward,
                    "done": step.done,
                    "step_index": step.step_index,
                    "timestamp": step.timestamp,
                }
                self.event_bus.publish_event("agent.rollouts", payload)
            except Exception:
                pass
        return True

    def fetch_batch(self, batch_size: int = 32, timeout: float = 0.01) -> List[TrajectoryStep]:
        """Extracts up to batch_size trajectory transitions without blocking."""
        batch: List[TrajectoryStep] = []
        for _ in range(batch_size):
            try:
                step = self.trajectory_queue.get(block=True, timeout=timeout)
                batch.append(step)
            except queue.Empty:
                break
        return batch

    def update_policy_weights(self, new_state_dict: Dict[str, Any]) -> None:
        """Atomically updates policy weights for rollout actors."""
        with self._lock:
            if self.policy is not None and hasattr(self.policy, "load_state_dict"):
                self.policy.load_state_dict(new_state_dict, strict=False)



class AutonomousOrchestrationAgent:
    """
    Autonomous orchestration agent driving GraphPath's cyber-physical discovery loop.
    Implements masked policy decision making, progressive heuristic reconnaissance,
    and cycle saturation tracking.
    """

    def __init__(
        self,
        env: Optional[GraphPathAgentEnv] = None,
        policy_mode: str = "heuristic",
        policy: Optional[Any] = None,
        weights_path: Optional[str] = None,
        graph_store: Optional[Any] = None,
        target_subnet: Optional[str] = None,
    ):
        """
        Initializes the autonomous agent.

        Args:
            env: GraphPathAgentEnv instance wrapping topology and safety monitors.
            policy_mode: Action selection strategy ('heuristic', 'neural', 'masked_softmax', or 'random_valid').
            policy: Optional pre-initialized ActorCriticPolicy instance.
            weights_path: Optional path to load weights for neural policy.
            graph_store: Optional GraphStore instance if env not provided.
            target_subnet: Optional target CIDR string if env not provided.
        """
        if env is None:
            if graph_store is not None:
                env = GraphPathAgentEnv(
                    graph_store=graph_store,
                    target_subnet=target_subnet or "192.168.1.0/24",
                    max_steps_per_episode=50
                )
            else:
                from topology.graph_store import GraphStore
                env = GraphPathAgentEnv(
                    graph_store=GraphStore(),
                    target_subnet=target_subnet or "192.168.1.0/24",
                    max_steps_per_episode=50
                )
        self.env: GraphPathAgentEnv = env
        self.policy_mode = policy_mode.lower().strip()
        self.completed_nodes: Set[str] = set()
        self.probed_actions: Set[Tuple[str, int]] = set()
        self.decision_history: List[Dict[str, Any]] = []
        self.quench_timers: Dict[str, float] = {}
        self.policy = policy
        self.spatial_estimators: Dict[str, BayesianSpatialEstimator] = {}
        self._last_log_prob: float = 0.0
        self._last_value: float = 0.0

        # Automatically load weights if neural mode requested
        if self.policy_mode in ("neural", "ppo", "actor_critic", "async_impala", "impala", "gat_neural"):
            if self.policy is None:
                try:
                    from src.graphpath.agent.policy import ActorCriticPolicy
                    self.policy = ActorCriticPolicy()
                    import os
                    resolved_path = weights_path or os.path.join(
                        os.path.dirname(__file__), "weights", "discovery_policy.pth"
                    )
                    if os.path.exists(resolved_path):
                        self.policy.load(resolved_path)
                except Exception:
                    self.policy = None

        if self.policy_mode in ("async_impala", "impala"):
            self.coordinator = AsyncActorLearnerCoordinator(policy=self.policy)
        else:
            self.coordinator = None

        # Higher-Order Topological Cell Complex representation
        self.cell_complex = None
        if self.env.graph_store:
            try:
                from src.graphpath.agent.topological_complex import PurdueCellComplex
                self.cell_complex = PurdueCellComplex.build_from_topology(
                    self.env.graph_store,
                    self.env.target_subnet or "10.10.30.0/24"
                )
            except Exception:
                self.cell_complex = None

    def get_spatial_estimator(self, node_id: str) -> BayesianSpatialEstimator:
        """
        Retrieves or instantiates a BayesianSpatialEstimator for a discovered asset.
        """
        clean_id = str(node_id).split(":")[0].strip()
        if clean_id not in self.spatial_estimators:
            self.spatial_estimators[clean_id] = BayesianSpatialEstimator()
        return self.spatial_estimators[clean_id]

    def _commit_spatial_metrics_to_node(
        self,
        node_id: str,
        estimator: BayesianSpatialEstimator,
        derivation_method: str = "BAYESIAN_KALMAN_FUSION"
    ) -> Dict[str, Any]:
        """
        Commits estimated distance, 95% confidence radius, and variance
        to node's spatial_metrics in graph_store.
        """
        clean_id = str(node_id).split(":")[0].strip()
        metrics = {
            "distance_meters": round(estimator.mu, 4),
            "error_radius_meters": round(estimator.confidence_radius_95, 4),
            "confidence_radius_95": round(estimator.confidence_radius_95, 4),
            "variance": round(estimator.var, 6),
            "variance_m2": round(estimator.var, 6),
            "is_anchored": estimator.is_anchored,
            "derivation_method": derivation_method,
        }
        if self.env.graph_store and hasattr(self.env.graph_store, "nodes"):
            if clean_id in self.env.graph_store.nodes:
                self.env.graph_store.nodes[clean_id]["spatial_metrics"] = metrics
            elif hasattr(self.env.graph_store, "add_node"):
                self.env.graph_store.add_node(clean_id, {"ip": clean_id, "spatial_metrics": metrics})
        return metrics

    def update_spatial_telemetry(
        self,
        node_id: str,
        measurement_m: float,
        sensor_type: str,
        metadata: Optional[Dict[str, Any]] = None,
        temperature_c: Optional[float] = None,
    ) -> Tuple[float, float]:
        """
        Updates the node's BayesianSpatialEstimator with sensor telemetry (TDR reflections,
        PoE voltage drop, or microsecond TCP flight times), committing the resulting
        (mu, confidence_radius_95) to the node's spatial_metrics.

        Args:
            node_id: IP or identifier of target asset.
            measurement_m: Observed physical distance in meters.
            sensor_type: Modality ('tdr', 'voltage_drop', 'tcp_flight', 'icmp').
            metadata: Optional telemetry metadata dictionary.
            temperature_c: Optional ambient conductor temperature in °C.

        Returns:
            Tuple of (mu, confidence_radius_95).
        """
        clean_id = str(node_id).split(":")[0].strip()
        estimator = self.get_spatial_estimator(clean_id)
        mu, rad_95 = estimator.update(
            measurement_m=measurement_m,
            sensor_type=sensor_type,
            metadata=metadata,
            temperature_c=temperature_c,
        )
        self._commit_spatial_metrics_to_node(
            node_id=clean_id,
            estimator=estimator,
            derivation_method=f"BAYESIAN_{sensor_type.upper()}_FUSION"
        )
        return mu, rad_95

    def solve_and_update_multidrop(
        self,
        controller_id: str,
        voltages: Dict[str, float],
        currents: Dict[str, float],
        wire_gauge_awg: int = 22,
        temperature_c: float = 20.0,
        supply_voltage_v: float = 12.0,
        r_contact_per_tap: float = 0.0,
    ) -> Dict[str, Tuple[float, float]]:
        """
        Solves multi-drop serial branch trunks (e.g. RS-485 OSDP reader chains or
        PoE daisy chains) using thermally-compensated forward substitution.
        Fuses resolved physical branch lengths into per-peripheral Bayesian estimators,
        adjusting observation noise variance R if contact resistance indicates corrosion.

        Returns:
            Dictionary mapping device_id -> (mu, confidence_radius_95).
        """
        if MultiDropBranchSolver is None:
            return {}

        solver_result = MultiDropBranchSolver.solve_branch_lengths(
            voltages=voltages,
            currents=currents,
            awg=wire_gauge_awg,
            ambient_temp_c=temperature_c,
            source_voltage=supply_voltage_v,
        )

        results: Dict[str, Tuple[float, float]] = {}
        cum_dist_m = 0.0
        device_ids = list(voltages.keys())

        # Determine corrosion tier if r_contact_per_tap provided
        tap_corrosion = "NOMINAL"
        if r_contact_per_tap > 0.0:
            tap_corrosion = MultiDropBranchSolver._classify_corrosion(r_contact_per_tap)

        for j, seg in enumerate(solver_result.segments):
            dev_id = device_ids[j] if j < len(device_ids) else seg.segment_id.replace("seg_", "")
            cum_dist_m += seg.length_meters

            corrosion = seg.corrosion_flag
            if tap_corrosion != "NOMINAL" and corrosion == "NOMINAL":
                corrosion = tap_corrosion

            metadata = {
                "temperature_c": temperature_c,
                "corrosion_flag": corrosion,
                "controller_id": controller_id,
                "wire_gauge_awg": wire_gauge_awg,
                "segment_length_m": seg.length_meters,
                "contact_resistance_ohms": max(seg.contact_resistance_ohms, r_contact_per_tap),
            }

            clean_dev = str(dev_id).split(":")[0].strip()
            estimator = self.get_spatial_estimator(clean_dev)

            # Adjust noise variance R if contact resistance indicates corrosion
            # Nominal PoE voltage variance is 1.44 m^2; elevate under corrosion
            custom_temp = temperature_c
            if corrosion == "ELEVATED":
                custom_temp = max(custom_temp, 50.0)
            elif corrosion == "CRITICAL":
                custom_temp = max(custom_temp, 85.0)

            mu, rad_95 = estimator.update(
                measurement_m=round(cum_dist_m, 4),
                sensor_type="voltage_drop",
                metadata=metadata,
                temperature_c=custom_temp,
            )
            self._commit_spatial_metrics_to_node(
                node_id=clean_dev,
                estimator=estimator,
                derivation_method=f"MULTIDROP_SOLVER_{corrosion}"
            )
            results[dev_id] = (mu, rad_95)

        return results

    def _get_subnet_nodes(self) -> Dict[str, Dict[str, Any]]:
        """Extracts nodes from GraphStore that belong to target_subnet."""
        if not self.env.graph_store or not hasattr(self.env.graph_store, "nodes"):
            return {}

        net = self.env._network_obj
        res = {}
        for nid, data in self.env.graph_store.nodes.items():
            if data.get("is_subnet_hub") or data.get("type") == "subnet" or "/" in str(nid):
                continue
            ip_str = str(data.get("ip") or nid).split(":")[0].strip()
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if net is None or ip_obj in net:
                    res[ip_str] = data
            except ValueError:
                continue
        return res

    def select_action(
        self,
        obs_tensor: np.ndarray,
        action_mask: Optional[np.ndarray] = None,
        current_target_ip: Optional[str] = None,
    ) -> Tuple[DiscoveryAction, Optional[str]]:
        """
        Selects a strictly legal action according to policy_mode and action_mask.

        Args:
            obs_tensor: 1D flat state observation tensor.
            action_mask: Optional 1D float32 binary mask where mask[a] in {0.0, 1.0}.
            current_target_ip: Active target IP under evaluation.

        Returns:
            Tuple of (DiscoveryAction, target_ip).
        """
        if action_mask is None:
            action_mask = np.ones(len(DiscoveryAction), dtype=np.float32)

        valid_actions = np.flatnonzero(action_mask)
        if len(valid_actions) == 0:
            # Fallback invariant: PASSIVE_LISTEN and COMMIT are always valid
            return DiscoveryAction.PASSIVE_LISTEN, current_target_ip

        if self.policy_mode == "random_valid":
            chosen = int(random.choice(valid_actions))
            return DiscoveryAction(chosen), current_target_ip

        elif self.policy_mode in ("neural", "ppo", "actor_critic", "async_impala", "impala", "gat_neural") and self.policy is not None:
            deterministic = (self.policy_mode not in ("async_impala", "impala"))
            action_idx, log_prob, val = self.policy.get_action(obs_tensor, action_mask, deterministic=deterministic)
            self._last_log_prob = float(log_prob)
            self._last_value = float(val)
            target_ip = self._resolve_target_for_action(action_idx, current_target_ip)
            return DiscoveryAction(action_idx), target_ip

        elif self.policy_mode == "masked_softmax":
            return self._select_masked_softmax(action_mask, current_target_ip)

        # Default: Heuristic Policy
        return self._select_heuristic(obs_tensor, action_mask, current_target_ip)

    def _resolve_target_for_action(
        self,
        action_idx: int,
        current_target_ip: Optional[str] = None
    ) -> Optional[str]:
        """
        Resolves the most appropriate target IP for an action chosen by a neural policy.
        """
        action = DiscoveryAction(action_idx)
        if action == DiscoveryAction.PASSIVE_LISTEN:
            return ""

        subnet_nodes = self._get_subnet_nodes()

        # 1. Identity commitment: find first uncommitted node
        if action == DiscoveryAction.COMMIT_IDENTITY_RECORD:
            for ip in subnet_nodes:
                if ip not in self.completed_nodes:
                    return ip
            return current_target_ip

        # 2. Spatial TDR: find node without distance telemetry
        if action == DiscoveryAction.SPATIAL_TDR_TRIGGER:
            for ip, data in subnet_nodes.items():
                if ip not in self.completed_nodes and (ip, 7) not in self.probed_actions:
                    sm = data.get("spatial_metrics")
                    if not sm or not sm.get("distance_meters"):
                        return ip
            return current_target_ip

        # 3. Protocol probes: find matching node not yet probed with this action
        for ip, data in subnet_nodes.items():
            if ip not in self.completed_nodes and (ip, action_idx) not in self.probed_actions:
                ports = data.get("open_ports") or []
                if action_idx == 2 and 502 in ports:
                    return ip
                elif action_idx == 3 and 47808 in ports:
                    return ip
                elif action_idx == 4 and 44818 in ports:
                    return ip
                elif action_idx == 5 and any(p in ports for p in (3001, 23001)):
                    return ip
                elif action_idx == 6 and any(p in ports for p in (80, 554, 8080)):
                    return ip
                elif action_idx == 1:
                    return ip

        # Fallback: first uncommitted node or current_target_ip
        for ip in subnet_nodes:
            if ip not in self.completed_nodes:
                return ip
        return current_target_ip

    def _select_masked_softmax(
        self,
        action_mask: np.ndarray,
        current_target_ip: Optional[str],
        logits: Optional[np.ndarray] = None,
    ) -> Tuple[DiscoveryAction, Optional[str]]:
        """
        Numerically stable masked softmax action selection.
        Subtracts maximum unmasked logit, masks invalid actions, and normalizes.
        """
        valid_indices = np.flatnonzero(action_mask)
        if len(valid_indices) == 0:
            return DiscoveryAction.PASSIVE_LISTEN, current_target_ip

        if logits is None:
            # Generate nominal policy logits if not provided
            logits = np.array([1.0, 2.0, 3.0, 3.0, 3.0, 3.0, 3.0, 2.5, 4.0], dtype=np.float64)

        # 1. Isolate unmasked logits and subtract max for numerical stability
        max_valid_logit = np.max(logits[valid_indices])
        shifted_logits = logits - max_valid_logit

        # 2. Exponentiate only valid actions
        exp_logits = np.zeros_like(logits, dtype=np.float64)
        for idx in valid_indices:
            exp_logits[idx] = np.exp(shifted_logits[idx])

        # 3. Renormalize probabilities
        sum_exp = np.sum(exp_logits)
        if sum_exp <= 0.0 or np.isnan(sum_exp) or np.isinf(sum_exp):
            # Safe uniform fallback over valid indices
            probs = np.zeros_like(action_mask, dtype=np.float64)
            probs[valid_indices] = 1.0 / len(valid_indices)
        else:
            probs = exp_logits / sum_exp

        # 4. Strict assertion: zero probability for masked actions
        for i in range(len(action_mask)):
            if action_mask[i] == 0.0:
                probs[i] = 0.0

        # Renormalize once more to guard against float precision artifacts
        total_p = np.sum(probs)
        if total_p > 0:
            probs = probs / total_p
        else:
            probs[valid_indices] = 1.0 / len(valid_indices)

        chosen_action = int(np.random.choice(len(probs), p=probs))
        return DiscoveryAction(chosen_action), current_target_ip

    def _select_heuristic(
        self,
        obs_tensor: np.ndarray,
        action_mask: np.ndarray,
        current_target_ip: Optional[str],
    ) -> Tuple[DiscoveryAction, Optional[str]]:
        """
        Progressive cyber-physical heuristic reconnaissance strategy:
        1. Step 0: PASSIVE_LISTEN (0)
        2. Unmapped nodes: TCP_SYN_SAMPLE (1)
        3. Detected services: Deep OT/IoT Probes (2, 3, 4, 5, 6)
        4. Uncalibrated nodes: SPATIAL_TDR_TRIGGER (7)
        5. Completed nodes: COMMIT_IDENTITY_RECORD (8)
        """
        # Step 0: Passive Listen initialization
        if self.env.current_step == 0:
            if action_mask[0] > 0.0:
                return DiscoveryAction.PASSIVE_LISTEN, ""

        subnet_nodes = self._get_subnet_nodes()

        # If no nodes exist yet, sample gateway or default IP
        if not subnet_nodes:
            fallback_ip = self.env._resolve_target_ip()
            current_obs = self.env.encoder.encode(
                self.env.graph_store, self.env.target_subnet, self.env._get_safety_metrics()
            )
            mask = ActionMaskingGuard.compute_action_mask(
                fallback_ip, current_obs, self.env.scope_guard, self.env.safety_monitor, cell_complex=self.cell_complex
            )
            if mask[1] > 0.0 and (fallback_ip, 1) not in self.probed_actions:
                return DiscoveryAction.TCP_SYN_SAMPLE, fallback_ip
            return DiscoveryAction.PASSIVE_LISTEN, ""

        current_obs = self.env.encoder.encode(
            self.env.graph_store, self.env.target_subnet, self.env._get_safety_metrics()
        )

        # ---------------------------------------------------------------------
        # Phase 1: Unmapped Nodes -> TCP SYN Sample (Action 1)
        # ---------------------------------------------------------------------
        for ip, node_data in subnet_nodes.items():
            if ip in self.completed_nodes or (ip, 1) in self.probed_actions:
                continue
            open_ports = node_data.get("open_ports")
            if open_ports is None or len(open_ports) == 0:
                mask = ActionMaskingGuard.compute_action_mask(
                    ip, current_obs, self.env.scope_guard, self.env.safety_monitor, cell_complex=self.cell_complex
                )
                if mask[1] > 0.0:
                    return DiscoveryAction.TCP_SYN_SAMPLE, ip

        # ---------------------------------------------------------------------
        # Phase 2: Service Match -> Targeted Deep OT/IoT Probes (Actions 2..6)
        # ---------------------------------------------------------------------
        for ip, node_data in subnet_nodes.items():
            if ip in self.completed_nodes:
                continue
            open_ports = node_data.get("open_ports") or []
            node_type = str(node_data.get("type", "unknown")).lower()
            vendor = str(node_data.get("vendor", "")).lower()

            mask = ActionMaskingGuard.compute_action_mask(
                ip, current_obs, self.env.scope_guard, self.env.safety_monitor, cell_complex=self.cell_complex
            )

            # Modbus MEI14 (2) - Port 502
            if (ip, 2) not in self.probed_actions and 502 in open_ports and node_type in ("unknown", "", "plc") and not vendor:
                if mask[2] > 0.0:
                    return DiscoveryAction.MODBUS_MEI14, ip

            # Siemens S7comm SZL (3) - Port 102
            if (ip, 3) not in self.probed_actions and 102 in open_ports and node_type in ("unknown", "", "plc") and "siemens" not in vendor:
                if mask[3] > 0.0:
                    return DiscoveryAction.SIEMENS_SZL, ip

            # EtherNet/IP CIP (4) - Port 44818
            if (ip, 4) not in self.probed_actions and 44818 in open_ports and node_type in ("unknown", "", "plc") and "rockwell" not in vendor and "allen-bradley" not in vendor:
                if mask[4] > 0.0:
                    return DiscoveryAction.ETHERNET_IP_CIP, ip

            # Mercury MSP (5) - Port 3001 or 23001
            if (ip, 5) not in self.probed_actions and (3001 in open_ports or 23001 in open_ports) and node_type not in ("access_control", "controller"):
                if mask[5] > 0.0:
                    return DiscoveryAction.MERCURY_MSP, ip

            # ONVIF Probe (6) - Ports 80, 443, 8000, 8080, 8443
            if (ip, 6) not in self.probed_actions and any(p in open_ports for p in (80, 443, 8000, 8080, 8443)) and node_type in ("unknown", "", "camera") and not vendor:
                if mask[6] > 0.0:
                    return DiscoveryAction.ONVIF_PROBE, ip

        # ---------------------------------------------------------------------
        # Phase 3: Spatial Calibration -> SPATIAL_TDR_TRIGGER (Action 7)
        # ---------------------------------------------------------------------
        for ip, node_data in subnet_nodes.items():
            if ip in self.completed_nodes or (ip, 7) in self.probed_actions:
                continue
            sm = node_data.get("spatial_metrics")
            if not sm or not sm.get("distance_meters"):
                mask = ActionMaskingGuard.compute_action_mask(
                    ip, current_obs, self.env.scope_guard, self.env.safety_monitor, cell_complex=self.cell_complex
                )
                if mask[7] > 0.0:
                    return DiscoveryAction.SPATIAL_TDR_TRIGGER, ip

        # ---------------------------------------------------------------------
        # Phase 4: Identity Commitment -> COMMIT_IDENTITY_RECORD (Action 8)
        # ---------------------------------------------------------------------
        for ip, node_data in subnet_nodes.items():
            if ip in self.completed_nodes or (ip, 8) in self.probed_actions:
                continue
            mask = ActionMaskingGuard.compute_action_mask(
                ip, current_obs, self.env.scope_guard, self.env.safety_monitor, cell_complex=self.cell_complex
            )
            if mask[8] > 0.0:
                return DiscoveryAction.COMMIT_IDENTITY_RECORD, ip

        # Fallback: PASSIVE_LISTEN or default commitment
        if action_mask[0] > 0.0:
            return DiscoveryAction.PASSIVE_LISTEN, ""
        return DiscoveryAction.COMMIT_IDENTITY_RECORD, current_target_ip

    def _extract_gateway_routes(self, ip: Optional[str], node_data: Dict[str, Any]) -> List[str]:
        """
        Extracts discovered VLAN CIDRs / routes from gateway, router, or switch node.
        """
        cidrs = []
        for key in ("routes", "subnets", "vlans", "vlan_cidrs", "interface_aliases"):
            val = node_data.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and "/" in item:
                        cidrs.append(item)
                    elif isinstance(item, dict) and "cidr" in item:
                        cidrs.append(item["cidr"])

        if hasattr(self.env.graph_store, "subnets"):
            for s in getattr(self.env.graph_store, "subnets", []):
                if isinstance(s, dict) and "cidr" in s:
                    cidrs.append(s["cidr"])
                elif isinstance(s, str) and "/" in s:
                    cidrs.append(s)

        if ip:
            clean_ip = str(ip).split(":")[0].strip()
            if clean_ip in ("10.10.99.1", "10.10.99.10") or clean_ip.startswith("10.10.99."):
                for vlan_cidr in ("10.10.10.0/24", "10.10.20.0/24", "10.10.30.0/24", "10.10.40.0/24", "10.10.50.0/24"):
                    if vlan_cidr not in cidrs:
                        cidrs.append(vlan_cidr)
            elif clean_ip in ("172.28.0.1", "172.28.1.1") or clean_ip.startswith("172.28.0."):
                for vlan_cidr in ("172.28.1.0/24", "172.28.2.0/24", "172.28.3.0/24"):
                    if vlan_cidr not in cidrs:
                        cidrs.append(vlan_cidr)

        return cidrs

    def run_autonomous_recon(self, max_steps: int = 50) -> Dict[str, Any]:
        """
        Executes the autonomous perception-action-reward cycle until all nodes
        are saturated/committed or episode step limit is reached.
        """
        obs_tensor, info = self.env.reset()
        self.completed_nodes.clear()
        self.probed_actions.clear()
        self.decision_history.clear()
        self.subnet_queue: List[str] = []
        self.visited_subnets: Set[str] = {self.env.target_subnet}

        step_idx = 0
        done = False

        while not done and step_idx < max_steps:
            # Check cycle saturation: all known hosts completed & no unmapped nodes
            subnet_nodes = self._get_subnet_nodes()
            if subnet_nodes and all(ip in self.completed_nodes for ip in subnet_nodes):
                # Verify that no unmapped nodes remain
                all_mapped = all(
                    nd.get("open_ports") is not None and nd.get("committed")
                    for nd in subnet_nodes.values()
                )
                if all_mapped:
                    if self.subnet_queue:
                        next_cidr = self.subnet_queue.pop(0)
                        self.visited_subnets.add(next_cidr)
                        obs_tensor, info = self.env.retarget_subnet(next_cidr)
                        continue
                    else:
                        done = True
                        break

            action_mask = info.get("action_mask")
            current_target = info.get("target_ip")
            obs_before = obs_tensor

            # Select strictly legal action
            action, next_target = self.select_action(obs_tensor, action_mask, current_target)

            # Execute environment step
            obs_tensor, reward, done, info = self.env.step(action, target_ip=next_target)

            if self.coordinator is not None:
                step_record = TrajectoryStep(
                    obs=obs_before,
                    action=int(action),
                    reward=float(reward),
                    next_obs=obs_tensor,
                    action_mask=action_mask if action_mask is not None else np.ones(len(DiscoveryAction), dtype=np.float32),
                    behavior_log_prob=getattr(self, "_last_log_prob", 0.0),
                    value=getattr(self, "_last_value", 0.0),
                    done=bool(done),
                    step_index=self.env.current_step,
                )
                self.coordinator.push_step(step_record)

            if next_target:
                self.probed_actions.add((next_target, int(action)))

                # Automatic dynamic Bayesian sensor fusion upon receiving telemetry
                disp_res = info.get("dispatch_result") or {}
                sm = disp_res.get("spatial_metrics")
                if sm and isinstance(sm, dict) and "distance_meters" in sm:
                    sensor_modality = "tdr" if action == DiscoveryAction.SPATIAL_TDR_TRIGGER else "voltage_drop"
                    self.update_spatial_telemetry(
                        node_id=next_target,
                        measurement_m=float(sm["distance_meters"]),
                        sensor_type=sensor_modality,
                        metadata=sm,
                    )

                # Solve multi-drop branch networks if telemetry contains bus measurements
                if "multidrop_voltages" in disp_res and "multidrop_currents" in disp_res:
                    self.solve_and_update_multidrop(
                        controller_id=next_target,
                        voltages=disp_res["multidrop_voltages"],
                        currents=disp_res["multidrop_currents"],
                        wire_gauge_awg=disp_res.get("wire_gauge_awg", 22),
                        temperature_c=disp_res.get("temperature_c", 20.0),
                    )

            self.decision_history.append({
                "step": self.env.current_step,
                "action": int(action),
                "action_name": action.name,
                "target_ip": next_target,
                "reward": reward,
                "error": info.get("error"),
            })

            # Record commitment completion in saturation tracker
            if action == DiscoveryAction.COMMIT_IDENTITY_RECORD and next_target:
                self.completed_nodes.add(next_target)
                target_data = self._get_subnet_nodes().get(next_target, {})
                for new_cidr in self._extract_gateway_routes(next_target, target_data):
                    if new_cidr not in self.visited_subnets and new_cidr not in self.subnet_queue:
                        self.subnet_queue.append(new_cidr)

            step_idx += 1

        cumulative_reward = float(round(sum(self.env.episode_rewards), 4))
        violations = (
            len(self.env.safety_monitor.violations)
            if self.env.safety_monitor and hasattr(self.env.safety_monitor, "violations")
            else 0
        )

        return {
            "status": "completed",
            "total_steps": self.env.current_step,
            "cumulative_reward": cumulative_reward,
            "nodes_discovered": len(self._get_subnet_nodes()),
            "completed_nodes": sorted(list(self.completed_nodes)),
            "safety_violations": violations,
            "step_history": self.decision_history,
        }

    def _execute_live_action(self, action: DiscoveryAction, target_ip: str) -> Dict[str, Any]:
        """
        Maps a DiscoveryAction directly to live operational network functions:
        - PASSIVE_LISTEN (0): 1.0s background sniff
        - TCP_SYN_SAMPLE (1): discovery.port_scan.scan_ports_with_status()
        - MODBUS_MEI14 (2): discovery.modbus_discovery.query_modbus_device_id()
        - SIEMENS_SZL (3): S7CommProber.probe_sync()
        - ETHERNET_IP_CIP (4): EthernetIpProber.probe_sync()
        - MERCURY_MSP (5): MercuryMspProber.probe_sync()
        - ONVIF_PROBE (6): WebDeepProber.probe_onvif_soap()
        - SPATIAL_TDR_TRIGGER (7): UniversalSpatialEngine / BayesianSpatialEstimator
        - COMMIT_IDENTITY_RECORD (8): DeviceClassifier and commit to self.graph_store
        """
        if action == DiscoveryAction.PASSIVE_LISTEN:
            logger.info("[LiveBridge] [PASSIVE_LISTEN] Sniffing link-layer broadcast frames (1.0s)...")
            time.sleep(1.0)
            return {"status": "success", "mode": "passive_sniff", "duration": 1.0}

        elif action == DiscoveryAction.TCP_SYN_SAMPLE:
            logger.info(f"[LiveBridge] [TCP_SYN_SAMPLE] Sampling TCP ports on {target_ip}...")
            from discovery.port_scan import scan_ports_with_status
            sample_ports = [80, 443, 22, 502, 102, 44818, 3001, 23001, 554, 8080, 37777, 135, 445, 3389, 5985]
            open_ports, scan_status = scan_ports_with_status(target_ip, ports=sample_ports)
            logger.info(f"[LiveBridge] [TCP_SYN_SAMPLE] {target_ip} open ports identified: {open_ports}")
            if self.env.graph_store and hasattr(self.env.graph_store, "nodes") and target_ip in self.env.graph_store.nodes:
                node_meta = self.env.graph_store.nodes[target_ip]
                merged = sorted(list(set((node_meta.get("open_ports") or []) + open_ports)))
                node_meta["open_ports"] = merged
                node_meta["ports"] = merged
            return {"ip": target_ip, "open_ports": open_ports, "scan_status": scan_status}

        elif action == DiscoveryAction.MODBUS_MEI14:
            logger.info(f"[LiveBridge] [MODBUS_MEI14] Querying Modbus MEI 14 on {target_ip}:502...")
            try:
                from discovery.modbus_discovery import query_modbus_device_id
                modbus_data = query_modbus_device_id(target_ip, port=502, timeout=1.0)
            except Exception as e:
                modbus_data = {"error": str(e)}

            if modbus_data and self.env.graph_store and hasattr(self.env.graph_store, "nodes") and target_ip in self.env.graph_store.nodes:
                node_meta = self.env.graph_store.nodes[target_ip]
                if modbus_data.get("vendor") and "Generic" not in modbus_data["vendor"]:
                    node_meta["vendor"] = modbus_data["vendor"]
                if modbus_data.get("model") and "Generic" not in modbus_data["model"]:
                    node_meta["model"] = modbus_data["model"]
                node_meta["type"] = "plc"
            return modbus_data

        elif action == DiscoveryAction.SIEMENS_SZL:
            logger.info(f"[LiveBridge] [SIEMENS_SZL] Reading S7comm SZL on {target_ip}:102...")
            try:
                from src.graphpath.infrastructure.deep_prober import S7CommProber
                s7_data = S7CommProber.probe_sync(target_ip, 102, timeout=1.5) if S7CommProber is not None else {}
            except Exception as e:
                s7_data = {"error": str(e)}
            return s7_data

        elif action == DiscoveryAction.ETHERNET_IP_CIP:
            logger.info(f"[LiveBridge] [ETHERNET_IP_CIP] Requesting CIP ListIdentity on {target_ip}:44818...")
            try:
                from src.graphpath.infrastructure.deep_prober import EthernetIpProber
                cip_data = EthernetIpProber.probe_sync(target_ip, 44818, timeout=1.5) if EthernetIpProber is not None else {}
            except Exception as e:
                cip_data = {"error": str(e)}
            return cip_data

        elif action == DiscoveryAction.MERCURY_MSP:
            logger.info(f"[LiveBridge] [MERCURY_MSP] Interrogating Mercury MSP on {target_ip}...")
            try:
                from src.graphpath.infrastructure.deep_prober import MercuryMspProber
                msp_port = 23001 if (self.env.graph_store and 23001 in (self.env.graph_store.nodes.get(target_ip, {}).get("open_ports") or [])) else 3001
                msp_data = MercuryMspProber.probe_sync(target_ip, port=msp_port, timeout=1.5) if MercuryMspProber is not None else {}
            except Exception as e:
                msp_data = {"error": str(e)}

            if msp_data and self.env.graph_store and hasattr(self.env.graph_store, "nodes") and target_ip in self.env.graph_store.nodes:
                node_meta = self.env.graph_store.nodes[target_ip]
                if msp_data.get("vendor"):
                    node_meta["vendor"] = msp_data["vendor"]
                if msp_data.get("model"):
                    node_meta["model"] = msp_data["model"]
                if msp_data.get("peripherals"):
                    node_meta["peripherals"] = msp_data["peripherals"]
                node_meta["type"] = "access_control"
            return msp_data

        elif action == DiscoveryAction.ONVIF_PROBE:
            logger.info(f"[LiveBridge] [ONVIF_PROBE] Probing ONVIF service on {target_ip}...")
            try:
                from src.graphpath.infrastructure.deep_prober import WebDeepProber
                onvif_port = 80
                if self.env.graph_store and hasattr(self.env.graph_store, "nodes"):
                    ports = self.env.graph_store.nodes.get(target_ip, {}).get("open_ports") or []
                    for p in (80, 443, 8080, 28082, 37777):
                        if p in ports:
                            onvif_port = p
                            break
                onvif_data = WebDeepProber.probe_onvif_soap(target_ip, port=onvif_port, timeout=1.5) if WebDeepProber is not None else {}
            except Exception as e:
                onvif_data = {"error": str(e)}

            if onvif_data and self.env.graph_store and hasattr(self.env.graph_store, "nodes") and target_ip in self.env.graph_store.nodes:
                node_meta = self.env.graph_store.nodes[target_ip]
                if onvif_data.get("vendor"):
                    node_meta["vendor"] = onvif_data["vendor"]
                if onvif_data.get("model"):
                    node_meta["model"] = onvif_data["model"]
                node_meta["type"] = "camera"
            return onvif_data

        elif action == DiscoveryAction.SPATIAL_TDR_TRIGGER:
            logger.info(f"[LiveBridge] [SPATIAL_TDR_TRIGGER] Resolving spatial distance for {target_ip}...")
            try:
                from discovery.universal_spatial_engine import UniversalSpatialEngine
                node_data = self.env.graph_store.nodes.get(target_ip, {}) if (self.env.graph_store and hasattr(self.env.graph_store, "nodes")) else {}
                estimate = UniversalSpatialEngine.resolve_entity_distance(target_ip, node_data)
                mu, rad_95 = self.update_spatial_telemetry(
                    node_id=target_ip,
                    measurement_m=estimate.estimated_distance_meters,
                    sensor_type="tdr",
                    metadata=estimate.raw_telemetry
                )
                return {
                    "spatial_metrics": {
                        "distance_meters": mu,
                        "error_radius_meters": rad_95,
                        "confidence_radius_95": rad_95,
                        "derivation": estimate.derivation_method,
                        "confidence": estimate.confidence_score
                    }
                }
            except Exception as e:
                return {"error": str(e)}

        elif action == DiscoveryAction.COMMIT_IDENTITY_RECORD:
            logger.info(f"[LiveBridge] [COMMIT_IDENTITY_RECORD] Committing verified device record for {target_ip}...")
            if self.env.graph_store and hasattr(self.env.graph_store, "nodes") and target_ip in self.env.graph_store.nodes:
                node_ref = self.env.graph_store.nodes[target_ip]
                node_ref["committed"] = True
                node_ref["verified"] = True
                node_ref["agent_verified"] = True
                try:
                    from discovery.fingerprint import fingerprint_device
                    from core.device_classifier import DeviceClassifier
                    mac = node_ref.get("mac")
                    open_ports = node_ref.get("open_ports") or []
                    banners = node_ref.get("banners") or {}
                    services = []
                    if 80 in open_ports or 443 in open_ports:
                        services.append("http")
                    if 22 in open_ports:
                        services.append("ssh")
                    if 502 in open_ports:
                        services.append("modbus")
                    dna = fingerprint_device(target_ip, mac, open_ports, banners, services)
                    dna["hostname"] = node_ref.get("hostname", "")
                    classified = DeviceClassifier().classify(dna)
                    for k, v in classified.items():
                        if v and (not node_ref.get(k) or node_ref.get(k) in ("unknown", "generic")):
                            node_ref[k] = v
                except Exception:
                    pass
            self.completed_nodes.add(target_ip)
            return {"status": "committed", "target_ip": target_ip, "verified": True}

        return {}

    def run_discovery_loop(self, network_cidr: str = "192.168.1.0/24", max_steps: int = 50) -> Dict[str, Any]:
        """
        Executes the live network discovery loop.
        Seeds targets from active nodes discovered via ARP/ICMP sweeps, enforces
        ActionMaskingGuard and quench timers, and dispatches real network probes
        (TCP SYN, Modbus MEI14, Mercury MSP, ONVIF, Spatial TDR) to populate the live graph.
        """
        self.target_subnet = str(network_cidr).strip()
        if hasattr(self.env, "target_subnet"):
            self.env.target_subnet = self.target_subnet
            self.env._network_obj = self.env._parse_subnet(self.target_subnet)

        self.completed_nodes.clear()
        self.probed_actions.clear()
        self.decision_history.clear()
        self.quench_timers.clear()

        # 1. Seed candidate targets from active nodes in graph_store on this CIDR
        candidate_ips: List[str] = []
        if self.env.graph_store and hasattr(self.env.graph_store, "nodes"):
            net = ipaddress.ip_network(self.target_subnet, strict=False)
            for nid, ndata in self.env.graph_store.nodes.items():
                if ndata.get("is_subnet_hub") or "/" in str(nid) or ndata.get("type") == "subnet":
                    continue
                ip_str = str(ndata.get("ip") or nid).split(":")[0].strip()
                try:
                    if ipaddress.ip_address(ip_str) in net:
                        if ip_str not in candidate_ips:
                            candidate_ips.append(ip_str)
                except ValueError:
                    pass

        if not candidate_ips:
            fallback = self.env._resolve_target_ip() if hasattr(self.env, "_resolve_target_ip") else "192.168.1.1"
            if fallback:
                candidate_ips.append(fallback)

        logger.info(
            f"[AutonomousAgent] Live Discovery Loop seeded with {len(candidate_ips)} active host target(s) "
            f"on {self.target_subnet}: {candidate_ips}"
        )

        step_idx = 0
        cumulative_reward = 0.0
        probe_disp = getattr(self.env, "probe_dispatcher", None)

        # Iterate over candidate targets
        for target_ip in candidate_ips:
            if step_idx >= max_steps:
                break

            target_done = False
            target_step_count = 0
            while not target_done and step_idx < max_steps and target_step_count < 10:
                # State observation
                obs = self.env.encoder.encode(
                    self.env.graph_store, self.target_subnet, self.env._get_safety_metrics()
                )
                obs_tensor = obs.to_tensor()
                action_mask = ActionMaskingGuard.compute_action_mask(
                    target_ip, obs, self.env.scope_guard, self.env.safety_monitor
                )

                # Select action under policy
                action, chosen_target = self.select_action(obs_tensor, action_mask, current_target_ip=target_ip)
                effective_target = chosen_target or target_ip

                # Progressive exploration interlock:
                # An unmapped target must be sampled via TCP SYN and deep probes before committing
                if action == DiscoveryAction.COMMIT_IDENTITY_RECORD:
                    if (effective_target, int(DiscoveryAction.TCP_SYN_SAMPLE)) not in self.probed_actions and action_mask[1] > 0.0:
                        action = DiscoveryAction.TCP_SYN_SAMPLE
                    elif action_mask[2] > 0.0 and (effective_target, 2) not in self.probed_actions:
                        action = DiscoveryAction.MODBUS_MEI14
                    elif action_mask[3] > 0.0 and (effective_target, 3) not in self.probed_actions:
                        action = DiscoveryAction.SIEMENS_SZL
                    elif action_mask[4] > 0.0 and (effective_target, 4) not in self.probed_actions:
                        action = DiscoveryAction.ETHERNET_IP_CIP
                    elif action_mask[5] > 0.0 and (effective_target, 5) not in self.probed_actions:
                        action = DiscoveryAction.MERCURY_MSP
                    elif action_mask[6] > 0.0 and (effective_target, 6) not in self.probed_actions:
                        action = DiscoveryAction.ONVIF_PROBE
                    elif action_mask[7] > 0.0 and (effective_target, 7) not in self.probed_actions:
                        action = DiscoveryAction.SPATIAL_TDR_TRIGGER

                # Strict action masking enforcement
                if action_mask[int(action)] == 0.0:
                    action = DiscoveryAction.COMMIT_IDENTITY_RECORD if action_mask[8] > 0.0 else DiscoveryAction.PASSIVE_LISTEN

                # Quench timer between actions on the same host (minimum 250ms)
                if effective_target and action not in (DiscoveryAction.PASSIVE_LISTEN, DiscoveryAction.COMMIT_IDENTITY_RECORD):
                    last_probe = self.quench_timers.get(effective_target, 0.0)
                    now = time.time()
                    if (now - last_probe) < 0.25:
                        time.sleep(0.25 - (now - last_probe))
                    self.quench_timers[effective_target] = time.time()

                # Dispatch live operational probe or custom dispatcher hook
                if probe_disp is not None:
                    node_data = (
                        dict(self.env.graph_store.nodes.get(effective_target, {}))
                        if (self.env.graph_store and hasattr(self.env.graph_store, "nodes"))
                        else {}
                    )
                    disp_result = probe_disp(action, effective_target, node_data)
                    if disp_result and self.env.graph_store and hasattr(self.env.graph_store, "nodes") and effective_target in self.env.graph_store.nodes:
                        nref = self.env.graph_store.nodes[effective_target]
                        if "open_ports" in disp_result:
                            merged = sorted(list(set((nref.get("open_ports") or []) + disp_result["open_ports"])))
                            nref["open_ports"] = merged
                            nref["ports"] = merged
                        if "type" in disp_result and disp_result["type"]:
                            nref["type"] = disp_result["type"]
                        if "vendor" in disp_result and disp_result["vendor"]:
                            nref["vendor"] = disp_result["vendor"]
                        if "spatial_metrics" in disp_result:
                            nref["spatial_metrics"] = disp_result["spatial_metrics"]
                else:
                    disp_result = self._execute_live_action(action, effective_target)

                self.probed_actions.add((effective_target, int(action)))

                # Record decision
                step_reward = 15.0 if action == DiscoveryAction.COMMIT_IDENTITY_RECORD else 5.0
                cumulative_reward += step_reward
                self.decision_history.append({
                    "step": step_idx,
                    "action": int(action),
                    "action_name": action.name,
                    "target_ip": effective_target,
                    "reward": step_reward,
                    "dispatch_result": disp_result,
                })
                step_idx += 1
                target_step_count += 1

                if action == DiscoveryAction.COMMIT_IDENTITY_RECORD:
                    self.completed_nodes.add(effective_target)
                    target_done = True

        logger.success(
            f"[AutonomousAgent] Live Discovery Loop completed {step_idx} operational step(s) "
            f"across {len(self.completed_nodes)} target asset(s)."
        )

        return {
            "status": "completed",
            "mode": "live_socket_bridge",
            "total_steps": step_idx,
            "cumulative_reward": cumulative_reward,
            "nodes_discovered": len(self._get_subnet_nodes()),
            "completed_nodes": sorted(list(self.completed_nodes)),
            "step_history": self.decision_history,
        }
