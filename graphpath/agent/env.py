"""
GraphPath Native Orchestration Agent - Gym Environment Integration & Action Dispatch Bus
Sprint 3: Reinforcement learning environment wrapper (GraphPathAgentEnv) with
multi-modal action dispatching, pre-execution action masking, and safety interlocks.
"""

import asyncio
import concurrent.futures
import inspect
import ipaddress
import socket
import time
from typing import Dict, Any, Optional, Tuple, Union, List, Callable
import numpy as np

from src.graphpath.agent.actions import (
    DiscoveryAction,
    ActionDefinition,
    ACTION_REGISTRY,
    get_action_definition,
)
from src.graphpath.agent.observation import (
    AgentObservation,
    AgentObservationEncoder,
    AGENT_COMMON_PORTS,
    PORT_TO_INDEX,
)
from src.graphpath.agent.guard import ActionMaskingGuard

# Graceful prober and spatial engine imports
try:
    from src.graphpath.infrastructure.deep_prober import (
        ModbusProber,
        S7CommProber,
        EthernetIpProber,
        MercuryMspProber,
        WebDeepProber,
    )
except ImportError:
    try:
        from infrastructure.deep_prober import (  # type: ignore
            ModbusProber,
            S7CommProber,
            EthernetIpProber,
            MercuryMspProber,
            WebDeepProber,
        )
    except ImportError:
        ModbusProber = None  # type: ignore
        S7CommProber = None  # type: ignore
        EthernetIpProber = None  # type: ignore
        MercuryMspProber = None  # type: ignore
        WebDeepProber = None  # type: ignore

try:
    from discovery.universal_spatial_engine import UniversalSpatialEngine
    from discovery.advanced_spatial_prober import AdvancedSpatialProber
except ImportError:
    try:
        from GraphPath.discovery.universal_spatial_engine import UniversalSpatialEngine  # type: ignore
        from GraphPath.discovery.advanced_spatial_prober import AdvancedSpatialProber  # type: ignore
    except ImportError:
        UniversalSpatialEngine = None  # type: ignore
        AdvancedSpatialProber = None  # type: ignore


class GraphPathAgentEnv:
    """
    Gym-compliant reinforcement learning environment wrapper for GraphPath's
    autonomous network discovery and industrial device identification agent.
    """

    def __init__(
        self,
        graph_store: Any,
        target_subnet: str = "192.168.1.0/24",
        safety_monitor: Optional[Any] = None,
        scope_guard: Optional[Any] = None,
        max_steps_per_episode: int = 50,
        default_target_ip: Optional[str] = None,
        probe_dispatcher: Optional[Callable[[DiscoveryAction, str, Dict[str, Any]], Dict[str, Any]]] = None,
    ):
        """
        Initializes the Gym environment.

        Args:
            graph_store: GraphStore instance containing network topology nodes and edges.
            target_subnet: Target CIDR block string being explored.
            safety_monitor: Optional SafetyMonitor tracking socket pool and rate limits.
            scope_guard: Optional ScopeAuthorizationGuard enforcing network boundaries.
            max_steps_per_episode: Maximum steps before episode termination (default: 50).
            default_target_ip: Optional default target IPv4 address.
            probe_dispatcher: Optional custom probe hook for testing/mocking network calls.
        """
        self.graph_store = graph_store
        self.target_subnet = target_subnet
        self.safety_monitor = safety_monitor
        self.scope_guard = scope_guard
        self.max_steps_per_episode = max_steps_per_episode
        self.default_target_ip = default_target_ip
        self.current_target_ip = default_target_ip
        self.probe_dispatcher = probe_dispatcher

        self.encoder = AgentObservationEncoder()
        self.current_step = 0
        self.episode_rewards: List[float] = []
        self._network_obj = self._parse_subnet(target_subnet)
        self._previous_violations_count = 0

    @staticmethod
    def _parse_subnet(cidr: str) -> Optional[ipaddress.IPv4Network]:
        try:
            return ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            return None

    def _execute_dispatch(self, func: Callable, *args, **kwargs) -> Any:
        """
        Safely dispatches prober call handling both synchronous methods and
        asynchronous coroutines to prevent event-loop deadlocks.
        """
        res = func(*args, **kwargs)
        if inspect.isawaitable(res):
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Running inside an active loop (e.g., pytest-asyncio or Testbench daemon)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        return pool.submit(asyncio.run, res).result()
                else:
                    return loop.run_until_complete(res)
            except RuntimeError:
                return asyncio.run(res)
        return res

    def _resolve_target_ip(
        self,
        target_ip: Optional[str] = None,
        action: Optional[DiscoveryAction] = None,
    ) -> str:
        """
        Resolves effective target IPv4 address with fallback hierarchy:
        1. Explicit target_ip argument
        2. self.current_target_ip
        3. First host in graph_store belonging to target_subnet
        4. Subnet gateway / .1 host
        PASSIVE_LISTEN (0) ignores target_ip as it operates on subnet broadcast.
        """
        if action == DiscoveryAction.PASSIVE_LISTEN:
            return ""

        if target_ip and str(target_ip).strip():
            resolved = str(target_ip).split(":")[0].strip()
            self.current_target_ip = resolved
            return resolved

        if self.current_target_ip and str(self.current_target_ip).strip():
            return self.current_target_ip

        # Fallback: Find first active host in graph_store belonging to target_subnet
        if self.graph_store and hasattr(self.graph_store, "nodes"):
            nodes = self.graph_store.nodes
            if self._network_obj:
                for nid, ndata in nodes.items():
                    ip_candidate = str(ndata.get("ip") or nid).split(":")[0].strip()
                    try:
                        if ipaddress.ip_address(ip_candidate) in self._network_obj:
                            self.current_target_ip = ip_candidate
                            return ip_candidate
                    except ValueError:
                        continue

        # Fallback: Subnet default gateway or .1 host
        if self._network_obj:
            hosts = list(self._network_obj.hosts())
            if hosts:
                fallback = str(hosts[0])
                self.current_target_ip = fallback
                return fallback

        return "192.168.1.1"

    def _get_safety_metrics(self) -> Dict[str, Any]:
        """Extracts safety metrics snapshot from SafetyMonitor."""
        if self.safety_monitor is None:
            return {}
        if hasattr(self.safety_monitor, "get_metrics_summary"):
            return self.safety_monitor.get_metrics_summary()
        if isinstance(self.safety_monitor, dict):
            return self.safety_monitor
        return {
            "max_socket_ceiling": getattr(self.safety_monitor, "max_socket_ceiling", 4),
            "active_connections": getattr(self.safety_monitor, "active_connections", {}),
        }

    def reset(self, target_ip: Optional[str] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Resets environment step counter and telemetry.
        Returns initial observation tensor (9731,) and action mask info dict.
        """
        self.current_step = 0
        self.episode_rewards.clear()
        self._previous_violations_count = 0

        if target_ip is not None:
            self.current_target_ip = target_ip

        obs = self.encoder.encode(self.graph_store, self.target_subnet, self._get_safety_metrics())
        effective_target = self._resolve_target_ip(self.current_target_ip)

        mask = ActionMaskingGuard.compute_action_mask(
            target_ip=effective_target,
            observation=obs,
            scope_guard=self.scope_guard,
            safety_monitor=self.safety_monitor,
        )

        info = {
            "action_mask": mask,
            "target_ip": effective_target,
            "step": 0,
            "target_subnet": self.target_subnet,
        }
        return obs.to_tensor(), info

    def retarget_subnet(self, new_cidr: str) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Dynamically retargets the exploration environment to a newly discovered CIDR block.
        Re-anchors target_subnet and _network_obj while preserving encoder state, history,
        and safety limits.

        Args:
            new_cidr: Subnet IPv4 CIDR string to explore (e.g., '10.10.20.0/24').

        Returns:
            Tuple of (new_obs_tensor, new_info).
        """
        self.target_subnet = str(new_cidr).strip()
        self._network_obj = self._parse_subnet(self.target_subnet)
        self.current_target_ip = None

        obs = self.encoder.encode(self.graph_store, self.target_subnet, self._get_safety_metrics())
        effective_target = self._resolve_target_ip(None)

        mask = ActionMaskingGuard.compute_action_mask(
            target_ip=effective_target,
            observation=obs,
            scope_guard=self.scope_guard,
            safety_monitor=self.safety_monitor,
        )

        info = {
            "action_mask": mask,
            "target_ip": effective_target,
            "step": self.current_step,
            "target_subnet": self.target_subnet,
        }
        return obs.to_tensor(), info

    def step(
        self,
        action: Union[int, DiscoveryAction],
        target_ip: Optional[str] = None,
    ) -> Tuple[np.ndarray, float, bool, Dict[str, Any]]:
        """
        Executes an agent action in the environment with pre-execution safety masking.

        Args:
            action: Discrete action index (0-8) or DiscoveryAction enum.
            target_ip: Optional target IP override.

        Returns:
            Tuple of (obs_tensor, reward, done, info).
        """
        try:
            action_enum = DiscoveryAction(int(action))
        except (ValueError, TypeError):
            raise ValueError(f"Invalid action {action}. Must be DiscoveryAction or int 0..8.")

        effective_target = self._resolve_target_ip(target_ip, action=action_enum)

        # 1. State observation prior to action
        pre_obs = self.encoder.encode(self.graph_store, self.target_subnet, self._get_safety_metrics())
        mask = ActionMaskingGuard.compute_action_mask(
            target_ip=effective_target,
            observation=pre_obs,
            scope_guard=self.scope_guard,
            safety_monitor=self.safety_monitor,
        )

        # 2. Illegal action interlock check
        if mask[int(action_enum)] == 0.0:
            self.current_step += 1
            done = (self.current_step >= self.max_steps_per_episode)
            reward = -10.0  # Strict, non-compounded penalty for illegal action
            self.episode_rewards.append(reward)
            info = {
                "error": "ILLEGAL_ACTION_MASKED",
                "action_mask": mask,
                "action": int(action_enum),
                "action_name": action_enum.name,
                "target_ip": effective_target,
                "step": self.current_step,
            }
            return pre_obs.to_tensor(), reward, done, info

        # 3. Snapshot pre-execution discovery state for reward calculation
        pre_hosts = int(np.sum(pre_obs.occupancy_bitmap))
        pre_ports = int(np.sum(pre_obs.port_matrix))
        pre_spatial_err = pre_obs.spatial_error_mean
        pre_node_data = (
            dict(self.graph_store.nodes.get(effective_target, {}))
            if hasattr(self.graph_store, "nodes")
            else {}
        )

        # 4. Dispatch legal action
        dispatch_result = self._dispatch_action(action_enum, effective_target, pre_node_data)

        # 5. Snapshot post-execution discovery state
        post_obs = self.encoder.encode(self.graph_store, self.target_subnet, self._get_safety_metrics())
        post_mask = ActionMaskingGuard.compute_action_mask(
            target_ip=effective_target,
            observation=post_obs,
            scope_guard=self.scope_guard,
            safety_monitor=self.safety_monitor,
        )

        post_hosts = int(np.sum(post_obs.occupancy_bitmap))
        post_ports = int(np.sum(post_obs.port_matrix))
        post_node_data = (
            dict(self.graph_store.nodes.get(effective_target, {}))
            if hasattr(self.graph_store, "nodes")
            else {}
        )

        # 6. Reward computation
        action_def = get_action_definition(action_enum)
        reward = self._compute_step_reward(
            action_def=action_def,
            pre_hosts=pre_hosts,
            post_hosts=post_hosts,
            pre_ports=pre_ports,
            post_ports=post_ports,
            pre_spatial_err=pre_spatial_err,
            post_spatial_err=post_obs.spatial_error_mean,
            pre_node_data=pre_node_data,
            post_node_data=post_node_data,
            action_enum=action_enum,
        )

        self.current_step += 1
        done = (self.current_step >= self.max_steps_per_episode)
        self.episode_rewards.append(reward)

        info = {
            "action": int(action_enum),
            "action_name": action_enum.name,
            "action_mask": post_mask,
            "target_ip": effective_target,
            "step": self.current_step,
            "dispatch_result": dispatch_result,
            "safety_metrics": self._get_safety_metrics(),
        }

        return post_obs.to_tensor(), reward, done, info

    def _dispatch_action(
        self,
        action: DiscoveryAction,
        target_ip: str,
        node_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Dispatches action across native probers or test hook."""
        if self.probe_dispatcher is not None:
            res = self.probe_dispatcher(action, target_ip, node_data)
            self._apply_dispatch_result_to_store(action, target_ip, res)
            return res

        action_def = get_action_definition(action)
        port = action_def.target_constraints.get("allowed_ports", [80])[0] if action_def.target_constraints.get("allowed_ports") else 80

        # Register connection in safety monitor if active cost > 0
        if action_def.base_socket_cost > 0 and self.safety_monitor and hasattr(self.safety_monitor, "register_connection_open"):
            self.safety_monitor.register_connection_open(target_ip, "agent_env", port)

        result: Dict[str, Any] = {}
        try:
            if action == DiscoveryAction.PASSIVE_LISTEN:
                result = {"status": "success", "frames_captured": 0, "mode": "passive_sniff"}

            elif action == DiscoveryAction.TCP_SYN_SAMPLE:
                # Default targeted port sample
                ports_to_check = [80, 443, 502, 102, 44818, 3001]
                discovered_open: List[int] = list(node_data.get("open_ports") or [])
                for p in ports_to_check:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.1)
                        if s.connect_ex((target_ip, p)) == 0:
                            if p not in discovered_open:
                                discovered_open.append(p)
                        s.close()
                    except Exception:
                        pass
                result = {"ip": target_ip, "open_ports": discovered_open}

            elif action == DiscoveryAction.MODBUS_MEI14:
                if ModbusProber is not None:
                    result = self._execute_dispatch(ModbusProber.probe_sync, target_ip, 502, timeout=1.5) or {}
                result.setdefault("type", "plc")

            elif action == DiscoveryAction.SIEMENS_SZL:
                if S7CommProber is not None:
                    result = self._execute_dispatch(S7CommProber.probe_sync, target_ip, 102, timeout=1.5) or {}
                result.setdefault("type", "plc")

            elif action == DiscoveryAction.ETHERNET_IP_CIP:
                if EthernetIpProber is not None:
                    result = self._execute_dispatch(EthernetIpProber.probe_sync, target_ip, 44818, timeout=1.5) or {}
                result.setdefault("type", "plc")

            elif action == DiscoveryAction.MERCURY_MSP:
                if MercuryMspProber is not None:
                    result = self._execute_dispatch(MercuryMspProber.probe_sync, target_ip, 3001, timeout=1.5) or {}
                result.setdefault("type", "access_control")

            elif action == DiscoveryAction.ONVIF_PROBE:
                if WebDeepProber is not None:
                    result = self._execute_dispatch(WebDeepProber.probe_onvif_soap, target_ip, 80, timeout=1.5) or {}
                result.setdefault("type", "camera")

            elif action == DiscoveryAction.SPATIAL_TDR_TRIGGER:
                if UniversalSpatialEngine is not None:
                    estimate = UniversalSpatialEngine.resolve_entity_distance(target_ip, node_data)
                    rad = 1.0 if estimate.confidence_score > 0.8 else 5.0
                    var_val = 0.25 if estimate.confidence_score > 0.8 else float((rad / 1.96) ** 2)
                    result = {
                        "spatial_metrics": {
                            "distance_meters": estimate.estimated_distance_meters,
                            "error_radius_meters": rad,
                            "confidence_radius_95": rad,
                            "variance": var_val,
                            "variance_m2": var_val,
                            "confidence": estimate.confidence_score,
                            "derivation_method": estimate.derivation_method,
                        }
                    }
                else:
                    result = {
                        "spatial_metrics": {
                            "distance_meters": 12.5,
                            "error_radius_meters": 0.98,
                            "confidence_radius_95": 0.98,
                            "variance": 0.25,
                            "variance_m2": 0.25,
                            "confidence": 0.85,
                            "derivation_method": "FALLBACK_TDR_CALIBRATION",
                        }
                    }

            elif action == DiscoveryAction.COMMIT_IDENTITY_RECORD:
                result = {"verified": True, "committed": True, "status": "committed"}

        finally:
            if action_def.base_socket_cost > 0 and self.safety_monitor and hasattr(self.safety_monitor, "register_connection_close"):
                self.safety_monitor.register_connection_close(target_ip)

        self._apply_dispatch_result_to_store(action, target_ip, result)
        return result

    def _apply_dispatch_result_to_store(
        self,
        action: DiscoveryAction,
        target_ip: str,
        result: Dict[str, Any],
    ) -> None:
        """Applies prober execution output into GraphStore."""
        if not self.graph_store or not hasattr(self.graph_store, "add_node"):
            return

        if action == DiscoveryAction.PASSIVE_LISTEN or not target_ip:
            return

        node_payload: Dict[str, Any] = {"ip": target_ip}
        for key in ("vendor", "model", "type", "firmware", "serial_number", "open_ports", "spatial_metrics", "verified", "committed", "status"):
            if key in result:
                node_payload[key] = result[key]

        self.graph_store.add_node(target_ip, node_payload)

        # If sub-peripherals are discovered (Mercury MSP), attach them
        if "peripherals" in result and hasattr(self.graph_store, "attach_sub_peripherals"):
            self.graph_store.attach_sub_peripherals(target_ip, result["peripherals"])

    def _compute_step_reward(
        self,
        action_def: ActionDefinition,
        pre_hosts: int,
        post_hosts: int,
        pre_ports: int,
        post_ports: int,
        pre_spatial_err: float,
        post_spatial_err: float,
        pre_node_data: Dict[str, Any],
        post_node_data: Dict[str, Any],
        action_enum: DiscoveryAction,
    ) -> float:
        """
        Multi-objective reward shaping:
        - Base nominal step cost: -0.1
        - Socket usage cost: -0.05 * base_socket_cost
        - Newly discovered host: +5.0
        - Newly discovered open port: +2.0
        - Resolved device type/vendor: +10.0
        - Resolved spatial distance: +5.0
        - Committed identity: +15.0
        - Safety violation penalty: -25.0 (CRITICAL), -10.0 (HIGH), -5.0 (MEDIUM)
        """
        step_cost = -0.1
        socket_cost = -0.05 * float(action_def.base_socket_cost)
        reward = step_cost + socket_cost

        # 1. Host discovery breadth
        if post_hosts > pre_hosts:
            reward += (post_hosts - pre_hosts) * 5.0

        # 2. Port discovery depth
        if post_ports > pre_ports:
            reward += (post_ports - pre_ports) * 2.0

        # 3. OT Classification & Identity Resolution
        pre_type = str(pre_node_data.get("type", "unknown")).lower()
        post_type = str(post_node_data.get("type", "unknown")).lower()
        if pre_type in ("unknown", "", "none") and post_type not in ("unknown", "", "none"):
            reward += 10.0

        pre_vendor = str(pre_node_data.get("vendor", "")).strip()
        post_vendor = str(post_node_data.get("vendor", "")).strip()
        if not pre_vendor and post_vendor:
            reward += 5.0

        # 4. Spatial distance resolution & Bayesian variance reduction
        if (pre_spatial_err == 0.0 or pre_spatial_err > post_spatial_err) and post_spatial_err > 0.0:
            reward += 5.0
        elif not pre_node_data.get("spatial_metrics") and post_node_data.get("spatial_metrics"):
            reward += 5.0

        # Spatial variance reduction bonus: rewards active uncertainty collapse on ambiguous nodes
        pre_sm = pre_node_data.get("spatial_metrics") or {}
        post_sm = post_node_data.get("spatial_metrics") or {}
        pre_var = pre_sm.get("variance") or pre_sm.get("variance_m2") or pre_sm.get("P")
        post_var = post_sm.get("variance") or post_sm.get("variance_m2") or post_sm.get("P")

        if pre_var is not None and post_var is not None and float(post_var) < float(pre_var):
            reward += 5.0
        elif pre_var is None and post_var is not None and float(post_var) <= 1.44:
            reward += 5.0

        # 5. Verified Identity Commitment
        if action_enum == DiscoveryAction.COMMIT_IDENTITY_RECORD:
            if post_node_data.get("committed") or post_node_data.get("verified"):
                reward += 15.0

        # 6. Safety monitor violation deduction
        if self.safety_monitor and hasattr(self.safety_monitor, "violations"):
            violations = getattr(self.safety_monitor, "violations", [])
            curr_count = len(violations)
            if curr_count > self._previous_violations_count:
                new_violations = violations[self._previous_violations_count:curr_count]
                for v in new_violations:
                    severity = getattr(v, "severity", "HIGH")
                    if severity == "CRITICAL":
                        reward -= 25.0
                    elif severity == "HIGH":
                        reward -= 10.0
                    else:
                        reward -= 5.0
                self._previous_violations_count = curr_count

        return float(round(reward, 4))

