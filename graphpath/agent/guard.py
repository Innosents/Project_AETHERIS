"""
GraphPath Native Orchestration Agent - Pre-Execution Action Masking Guardrail & eBPF Fragility Monitor
Subsystem I: Safety interlocks, eBPF real-time hardware fragility detection,
socket pool headroom, concurrency ceilings, and closed-port protocol gating.
"""

from dataclasses import dataclass, field
import threading
import time
from typing import Optional, Any, Dict, Tuple, List
import numpy as np

from src.graphpath.agent.actions import (
    DiscoveryAction,
    get_action_definition,
)
from src.graphpath.agent.observation import AgentObservation


@dataclass
class EBPFMetricRecord:
    """Real-time kernel socket telemetry record per target endpoint."""
    target_ip: str
    syn_ack_latency_us: float = 0.0
    rst_count: int = 0
    tcp_window_size: int = 65535
    r_contact_ohms: float = 0.0
    spatial_variance: float = 0.0
    timestamp: float = field(default_factory=time.time)


class EBPFHardwareFragilityReader:
    """
    O(1) circular ring buffer and memory-mapped reader for live eBPF kernel socket metrics.
    Monitors TCP SYN-ACK latency, reset (RST) surges, receive window collapse,
    and physical conductor contact resistance to protect fragile industrial RTOS stacks.
    """

    DEFAULT_MAX_SYN_ACK_LATENCY_US: float = 250_000.0  # 250ms threshold
    DEFAULT_MAX_RST_COUNT: int = 3                      # >= 3 resets in window
    DEFAULT_MIN_TCP_WINDOW_BYTES: int = 512             # < 512 bytes indicates socket backpressure
    DEFAULT_MAX_R_CONTACT_OHMS: float = 0.35            # 0.35 ohms critical corrosion

    _instance = None
    _lock = threading.RLock()

    @classmethod
    def get_instance(cls) -> "EBPFHardwareFragilityReader":
        """Singleton accessor for process-wide eBPF fragility reader."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self, capacity: int = 1024):
        self.capacity = capacity
        self._records: Dict[str, EBPFMetricRecord] = {}
        self._ring: List[Optional[str]] = [None] * capacity
        self._head: int = 0
        self._rw_lock = threading.RLock()

    def update_metrics(
        self,
        target_ip: str,
        syn_ack_latency_us: float = 0.0,
        rst_count: int = 0,
        tcp_window_size: int = 65535,
        r_contact_ohms: float = 0.0,
        spatial_variance: float = 0.0,
        timestamp: Optional[float] = None,
    ) -> None:
        """
        O(1) ingestion of kernel socket metrics for target IP.
        """
        clean_ip = str(target_ip).split(":")[0].strip()
        ts = float(timestamp) if timestamp is not None else time.time()
        record = EBPFMetricRecord(
            target_ip=clean_ip,
            syn_ack_latency_us=float(syn_ack_latency_us),
            rst_count=int(rst_count),
            tcp_window_size=int(tcp_window_size),
            r_contact_ohms=float(r_contact_ohms),
            spatial_variance=float(spatial_variance),
            timestamp=ts,
        )
        with self._rw_lock:
            old_ip = self._ring[self._head]
            if old_ip and old_ip != clean_ip and old_ip in self._records:
                # Evict oldest record if capacity exceeded
                del self._records[old_ip]
            self._ring[self._head] = clean_ip
            self._head = (self._head + 1) % self.capacity
            self._records[clean_ip] = record

    record_observation = update_metrics

    def get_metrics(self, target_ip: str) -> Optional[EBPFMetricRecord]:
        """O(1) retrieval of live kernel socket metrics."""
        clean_ip = str(target_ip).split(":")[0].strip()
        with self._rw_lock:
            return self._records.get(clean_ip)

    def is_hardware_fragile(self, target_ip: str) -> Tuple[bool, str]:
        """
        Evaluates whether target endpoint shows signs of RTOS stack or physical degradation.
        """
        rec = self.get_metrics(target_ip)
        if rec is None:
            return False, "nominal"

        if rec.syn_ack_latency_us > self.DEFAULT_MAX_SYN_ACK_LATENCY_US:
            return True, f"SYN-ACK latency spike ({rec.syn_ack_latency_us:.1f}us > {self.DEFAULT_MAX_SYN_ACK_LATENCY_US:.1f}us)"
        if rec.rst_count >= self.DEFAULT_MAX_RST_COUNT:
            return True, f"TCP reset spike ({rec.rst_count} RSTs in window)"
        if rec.tcp_window_size < self.DEFAULT_MIN_TCP_WINDOW_BYTES:
            return True, f"TCP receive window collapse ({rec.tcp_window_size}B < {self.DEFAULT_MIN_TCP_WINDOW_BYTES}B)"
        if rec.r_contact_ohms >= self.DEFAULT_MAX_R_CONTACT_OHMS:
            return True, f"Critical contact resistance ({rec.r_contact_ohms:.3f} ohms >= {self.DEFAULT_MAX_R_CONTACT_OHMS:.3f} ohms)"

        return False, "nominal"

    def reset(self) -> None:
        """Clears metric records (used in test fixtures)."""
        with self._rw_lock:
            self._records.clear()
            self._ring = [None] * self.capacity
            self._head = 0


class ActionMaskingGuard:
    """
    Computes a valid discrete action mask M(s) in {0.0, 1.0}^9 ensuring the
    autonomous agent cannot sample or execute unsafe, out-of-scope,
    over-budget, or protocol-mismatched actions.
    Augmented with real-time eBPF hardware fragility monitoring.
    """

    # Gated action port requirements
    MODBUS_REQUIRED_PORTS = (502,)
    SIEMENS_REQUIRED_PORTS = (102,)
    ETHERNET_IP_REQUIRED_PORTS = (44818,)
    MERCURY_REQUIRED_PORTS = (3001, 23001)
    ONVIF_REQUIRED_PORTS = (80, 443, 8000, 8080, 8443)

    @classmethod
    def compute_action_mask(
        cls,
        target_ip: str,
        observation: AgentObservation,
        scope_guard: Optional[Any] = None,
        safety_monitor: Optional[Any] = None,
        active_connections: int = 0,
        socket_limit: Optional[int] = None,
        ebpf_reader: Optional[EBPFHardwareFragilityReader] = None,
        cell_complex: Optional[Any] = None,
    ) -> np.ndarray:
        """
        Calculates the 9-dimensional binary action mask for target_ip.

        Args:
            target_ip: Target IPv4 string being evaluated.
            observation: Current AgentObservation state representation.
            scope_guard: Optional ScopeAuthorizationGuard enforcing CIDR allow/deny lists.
            safety_monitor: Optional SafetyMonitor tracking socket concurrency & bursts.
            active_connections: Live concurrent sockets already open to target_ip.
            socket_limit: Optional target-specific socket ceiling (e.g., 2 for fragile PLCs).
            ebpf_reader: Optional EBPFHardwareFragilityReader providing kernel TCP backpressure metrics.
            cell_complex: Optional PurdueCellComplex providing higher-order topological zone propagation.

        Returns:
            1D np.ndarray of shape (9,) with dtype=np.float32.
        """
        # Initialize all 9 actions as enabled
        mask = np.ones(len(DiscoveryAction), dtype=np.float32)

        # ---------------------------------------------------------------------
        # 1. Automatic Socket Limit Deduction (Safeguard 2)
        # ---------------------------------------------------------------------
        effective_limit = socket_limit
        if effective_limit is None and safety_monitor is not None:
            effective_limit = getattr(safety_monitor, "max_socket_ceiling", None)

        # Resolve active connections from safety_monitor if not explicitly provided
        if active_connections == 0 and safety_monitor is not None:
            conns = getattr(safety_monitor, "active_connections", {})
            if isinstance(conns, dict):
                active_connections = conns.get(target_ip, 0)

        # ---------------------------------------------------------------------
        # 2. Scope Interlock (DO-NOT-SCAN Exclusions & Out-of-Scope CIDRs)
        # ---------------------------------------------------------------------
        if scope_guard is not None:
            try:
                res = scope_guard.is_permitted(target_ip)
                is_permitted = res[0] if isinstance(res, (tuple, list)) else bool(res)
            except Exception:
                is_permitted = False

            if not is_permitted:
                # Active probes (actions 1 through 7) are strictly blocked
                mask[1:8] = 0.0

        # ---------------------------------------------------------------------
        # 3. Global Socket Budget & Concurrency Ceiling Interlocks
        # ---------------------------------------------------------------------
        for action in DiscoveryAction:
            action_idx = int(action)
            # Actions 0 (PASSIVE_LISTEN) and 8 (COMMIT_IDENTITY_RECORD) bypass socket checks
            if action_idx in (0, 8):
                continue

            action_def = get_action_definition(action)
            cost = action_def.base_socket_cost

            # Check global remaining socket pool headroom
            if observation.socket_budget_remaining < cost:
                mask[action_idx] = 0.0
                continue

            # Check target-specific concurrency limit (Fragile PLC saturation protection)
            if effective_limit is not None:
                if active_connections + cost > effective_limit:
                    mask[action_idx] = 0.0
                    continue

        # ---------------------------------------------------------------------
        # 4. Dynamic eBPF Hardware Fragility Guard & Higher-Order Zone Propagation
        # ---------------------------------------------------------------------
        reader = ebpf_reader or EBPFHardwareFragilityReader.get_instance()
        metrics = reader.get_metrics(target_ip)
        is_target_distressed = False
        if metrics is not None:
            # SYN-ACK latency spike > 250ms indicates RTOS stack saturation
            if metrics.syn_ack_latency_us > reader.DEFAULT_MAX_SYN_ACK_LATENCY_US:
                mask[1:8] = 0.0
                is_target_distressed = True

            # Rapid TCP resets or zero window backpressure
            if metrics.rst_count >= reader.DEFAULT_MAX_RST_COUNT:
                mask[1:7] = 0.0
                is_target_distressed = True

            if metrics.tcp_window_size < reader.DEFAULT_MIN_TCP_WINDOW_BYTES:
                mask[1:7] = 0.0
                is_target_distressed = True

            # Conductor corrosion > 0.35 ohms makes TDR pulse reflectometry hazardous/erratic
            if metrics.r_contact_ohms >= reader.DEFAULT_MAX_R_CONTACT_OHMS:
                mask[7] = 0.0

        # Higher-order topological zone-wide safety propagation
        if cell_complex is not None and hasattr(cell_complex, "propagate_zone_distress"):
            distressed_ips = []
            if hasattr(reader, "_records"):
                for ip_str in reader._records.keys():
                    is_fragile, _ = reader.is_hardware_fragile(ip_str)
                    if is_fragile:
                        distressed_ips.append(ip_str)
            if is_target_distressed and target_ip not in distressed_ips:
                distressed_ips.append(target_ip)

            if distressed_ips:
                zone_scores, quarantined_ips = cell_complex.propagate_zone_distress(distressed_ips)
                clean_target = str(target_ip).split(":")[0].strip()
                if clean_target in quarantined_ips:
                    target_zone = getattr(cell_complex, "node_zone_map", {}).get(clean_target)
                    if target_zone in ("L0_PROCESS", "L1_BASIC_CONTROL"):
                        mask[1:8] = 0.0
                    elif clean_target in distressed_ips:
                        mask[1:7] = 0.0

        # ---------------------------------------------------------------------
        # 5. Closed Port Gating (Safeguard 1)
        # ---------------------------------------------------------------------
        # MODBUS_MEI14 (2): Requires port 502
        if mask[2] > 0.0:
            if not observation.is_port_active(target_ip, 502):
                mask[2] = 0.0

        # SIEMENS_SZL (3): Requires port 102
        if mask[3] > 0.0:
            if not observation.is_port_active(target_ip, 102):
                mask[3] = 0.0

        # ETHERNET_IP_CIP (4): Requires port 44818
        if mask[4] > 0.0:
            if not observation.is_port_active(target_ip, 44818):
                mask[4] = 0.0

        # MERCURY_MSP (5): Requires port 3001 or 23001
        if mask[5] > 0.0:
            has_msp = observation.is_port_active(target_ip, 3001) or observation.is_port_active(target_ip, 23001)
            if not has_msp:
                mask[5] = 0.0

        # ONVIF_PROBE (6): Requires web/camera ports (80, 443, 8000, 8080, 8443)
        if mask[6] > 0.0:
            has_onvif = any(observation.is_port_active(target_ip, p) for p in cls.ONVIF_REQUIRED_PORTS)
            if not has_onvif:
                mask[6] = 0.0

        # ---------------------------------------------------------------------
        # 6. Spatial Variance Convergence Interlock (Redundant TDR Prevention)
        # ---------------------------------------------------------------------
        # SPATIAL_TDR_TRIGGER (7): If target host's physical location has already
        # collapsed to high certainty (variance <= 0.25 m^2 via TDR or categorical anchor),
        # mask out action 7 to avoid redundant packet transmission and preserve socket headroom.
        if mask[7] > 0.0 and observation is not None:
            clean_ip = str(target_ip).split(":")[0].strip() if target_ip else ""
            spatial_var = None
            if hasattr(observation, "spatial_variance") and isinstance(observation.spatial_variance, dict):
                spatial_var = observation.spatial_variance.get(target_ip)
                if spatial_var is None and clean_ip:
                    spatial_var = observation.spatial_variance.get(clean_ip)

            if spatial_var is not None and float(spatial_var) <= 0.25:
                mask[7] = 0.0

        # ---------------------------------------------------------------------
        # 7. Immutable Invariants: PASSIVE_LISTEN (0) and COMMIT (8) ALWAYS Valid
        # ---------------------------------------------------------------------
        mask[0] = 1.0
        mask[8] = 1.0

        return mask.astype(np.float32)
