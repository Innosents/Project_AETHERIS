"""
Project AETHERIS - Spatial Bayesian Fusion Engine (Pillar 3)
Calculates exact posterior probability distributions across device archetypes
using discrete likelihood matrices and log-space numerical normalization.
Locks hardware switch fabric delay offsets and recalibrates kernel turnaround
baselines from empirical ground-truth measurements.
"""

import math
from pathlib import Path
import networkx as nx
from typing import Dict, List, Any, Optional

from aetheris.core.ports.spatial_bayesian_port import (
    BayesianFusionPort,
    SpatialSolverPort,
)
from aetheris.core.topologies import Endpoint, Unmanaged_Switch

# Locked Switch Fabric & ASIC PHY Delay Offset (1.20 µs calibrated hardware baseline)
LOCKED_SWITCH_FABRIC_DELAY_OFFSET_US: float = 1.20
LOCKED_SWITCH_FABRIC_DELAY_OFFSET_SEC: float = 1.20e-6

# Intermediate Switch Hop Penalty (18.5 ns store-and-forward switching latency)
INTERMEDIATE_HOP_PENALTY_NS: float = 18.5
INTERMEDIATE_HOP_PENALTY_US: float = 0.0185
INTERMEDIATE_HOP_PENALTY_SEC: float = 18.5e-9

# Empirically recalibrated kernel turnaround baselines in microseconds
RECALIBRATED_KERNEL_BASELINES_US: Dict[str, float] = {
    "WINDOWS_HOST": 950.0,
    "LINUX_SERVER": 1100.0,
    "CCTV_VIDEO": 2180.0,
    "NETWORK_INFRASTRUCTURE": 190.0,
    "INDUSTRIAL_OT": 280.0,
    "VOIP_TELEPHONY": 980.0,
    "GENERIC_HOST": 1000.0,
}

class BayesianEvidenceFusion(BayesianFusionPort):
    ARCHETYPES = [
        "WINDOWS_HOST", "VOIP_TELEPHONY", "INDUSTRIAL_OT",
        "CCTV_VIDEO", "NETWORK_INFRASTRUCTURE", "LINUX_SERVER",
    ]
    DEFAULT_PRIOR = 1.0 / len(ARCHETYPES)

    # Conditional likelihoods: P(Evidence | Archetype)
    LIKELIHOOD_TABLE = {
        "ttl_windows_128": {
            "WINDOWS_HOST": 0.90, "VOIP_TELEPHONY": 0.05, "INDUSTRIAL_OT": 0.05,
            "CCTV_VIDEO": 0.05, "NETWORK_INFRASTRUCTURE": 0.02, "LINUX_SERVER": 0.05,
        },
        "ttl_linux_64": {
            "WINDOWS_HOST": 0.05, "VOIP_TELEPHONY": 0.60, "INDUSTRIAL_OT": 0.40,
            "CCTV_VIDEO": 0.70, "NETWORK_INFRASTRUCTURE": 0.20, "LINUX_SERVER": 0.95,
        },
        "ttl_network_255": {
            "WINDOWS_HOST": 0.02, "VOIP_TELEPHONY": 0.10, "INDUSTRIAL_OT": 0.20,
            "CCTV_VIDEO": 0.05, "NETWORK_INFRASTRUCTURE": 0.95, "LINUX_SERVER": 0.10,
        },
        "port_smb_445": {
            "WINDOWS_HOST": 0.95, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.01,
            "CCTV_VIDEO": 0.01, "NETWORK_INFRASTRUCTURE": 0.01, "LINUX_SERVER": 0.10,
        },
        "port_sip_5060": {
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.98, "INDUSTRIAL_OT": 0.01,
            "CCTV_VIDEO": 0.02, "NETWORK_INFRASTRUCTURE": 0.01, "LINUX_SERVER": 0.05,
        },
        "port_modbus_502": {
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.99,
            "CCTV_VIDEO": 0.01, "NETWORK_INFRASTRUCTURE": 0.02, "LINUX_SERVER": 0.02,
        },
        "modbus_protocol_502": {
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.99,
            "CCTV_VIDEO": 0.01, "NETWORK_INFRASTRUCTURE": 0.02, "LINUX_SERVER": 0.02,
        },
        "port_rtsp_554": {
            "WINDOWS_HOST": 0.02, "VOIP_TELEPHONY": 0.05, "INDUSTRIAL_OT": 0.01,
            "CCTV_VIDEO": 0.96, "NETWORK_INFRASTRUCTURE": 0.01, "LINUX_SERVER": 0.05,
        },
        "port_snmp_161": {
            "WINDOWS_HOST": 0.20, "VOIP_TELEPHONY": 0.15, "INDUSTRIAL_OT": 0.30,
            "CCTV_VIDEO": 0.10, "NETWORK_INFRASTRUCTURE": 0.92, "LINUX_SERVER": 0.35,
        },
        "port_mercury_3001": {
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.99,
            "CCTV_VIDEO": 0.01, "NETWORK_INFRASTRUCTURE": 0.01, "LINUX_SERVER": 0.02,
        },
        "mercury_protocol_3001": {
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.99,
            "CCTV_VIDEO": 0.01, "NETWORK_INFRASTRUCTURE": 0.01, "LINUX_SERVER": 0.02,
        },
        "port_onvif_80": {
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.05,
            "CCTV_VIDEO": 0.99, "NETWORK_INFRASTRUCTURE": 0.05, "LINUX_SERVER": 0.05,
        },
        "onvif_soap_service": {
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.05,
            "CCTV_VIDEO": 0.99, "NETWORK_INFRASTRUCTURE": 0.05, "LINUX_SERVER": 0.05,
        },
        "port_bacnet_47808": {
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.99,
            "CCTV_VIDEO": 0.01, "NETWORK_INFRASTRUCTURE": 0.02, "LINUX_SERVER": 0.02,
        },
        "bacnet_protocol_47808": {
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.99,
            "CCTV_VIDEO": 0.01, "NETWORK_INFRASTRUCTURE": 0.02, "LINUX_SERVER": 0.02,
        },
    }

    @classmethod
    def get_switch_fabric_offset_us(cls) -> float:
        return LOCKED_SWITCH_FABRIC_DELAY_OFFSET_US

    @classmethod
    def get_switch_fabric_offset_sec(cls) -> float:
        return LOCKED_SWITCH_FABRIC_DELAY_OFFSET_SEC

    @classmethod
    def get_intermediate_hop_penalty_us(
        cls,
        identifier_or_port: Optional[str] = None,
        switchport_map: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Returns intermediate switch hop penalty in microseconds (0.0185 µs / 18.5 ns).
        Applies store-and-forward switching latency deduction to Port 1 (Trunk/Bridge) endpoints.
        """
        if identifier_or_port is None:
            return INTERMEDIATE_HOP_PENALTY_US

        ident = str(identifier_or_port).strip()
        if ident.lower() in ("port 1", "port_1", "port1", "trunk_bridge", "trunk"):
            return INTERMEDIATE_HOP_PENALTY_US

        ports = switchport_map if switchport_map is not None else cls.load_gateway_switchports()
        entry = ports.get(ident) or ports.get(ident.upper()) or ports.get(ident.lower())
        if entry:
            port_name = str(entry.get("switchport", "")).strip().lower()
            port_type = str(entry.get("port_type", "")).strip().upper()
            if port_name in ("port 1", "port1") or port_type == "TRUNK_BRIDGE":
                return INTERMEDIATE_HOP_PENALTY_US
            return 0.0

        return 0.0

    @classmethod
    def get_intermediate_hop_penalty_ns(
        cls,
        identifier_or_port: Optional[str] = None,
        switchport_map: Optional[Dict[str, Any]] = None
    ) -> float:
        """Returns intermediate switch hop penalty in nanoseconds (18.5 ns for Port 1 / trunk)."""
        return cls.get_intermediate_hop_penalty_us(identifier_or_port, switchport_map) * 1000.0

    @classmethod
    def get_intermediate_hop_penalty_sec(
        cls,
        identifier_or_port: Optional[str] = None,
        switchport_map: Optional[Dict[str, Any]] = None
    ) -> float:
        """Returns intermediate switch hop penalty in seconds (18.5e-9 s for Port 1 / trunk)."""
        return cls.get_intermediate_hop_penalty_us(identifier_or_port, switchport_map) * 1e-6

    @classmethod
    def get_serialization_penalty_us(
        cls,
        identifier_or_port: Optional[str] = None,
        switchport_map: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Returns transmission serialization delay penalty in microseconds.
        100BASE-TX drops (Port 3) incur 5.12 µs per 64-byte frame (64*8/100Mbps).
        Gigabit drops (Port 1, Port 2) incur 0.512 µs.
        """
        if identifier_or_port is None:
            return 0.0

        ident = str(identifier_or_port).strip()
        if ident.lower() in ("port 3", "port_3", "port3", "100base-tx", "100m"):
            return 5.12

        ports = switchport_map if switchport_map is not None else cls.load_gateway_switchports()
        entry = ports.get(ident) or ports.get(ident.upper()) or ports.get(ident.lower())
        if entry:
            port_name = str(entry.get("switchport", "")).strip().lower()
            speed = entry.get("link_speed_mbps")
            port_type = str(entry.get("port_type", "")).strip().upper()
            if port_name in ("port 3", "port3", "port 3 (100m)") or speed == 100 or port_type == "DIRECT_DROP_100M":
                return 5.12
        return 0.0

    @classmethod
    def get_calibrated_kernel_turnaround_us(cls, archetype: str) -> float:
        """Retrieves empirical kernel turnaround baseline for the specified archetype in microseconds."""
        return RECALIBRATED_KERNEL_BASELINES_US.get(archetype, RECALIBRATED_KERNEL_BASELINES_US["GENERIC_HOST"])

    @classmethod
    def get_calibrated_kernel_turnaround_sec(cls, archetype: str) -> float:
        """Retrieves empirical kernel turnaround baseline for the specified archetype in seconds."""
        return cls.get_calibrated_kernel_turnaround_us(archetype) * 1e-6

    @classmethod
    def load_physical_ground_truth(cls, db_path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Loads validated physical cable measurements from spatial_ledger.db.
        Unifies physical_ground_truth and device_registry tables.
        Returns: { identifier: { 'device_label': ..., 'measured_length_m': ..., 'medium': ... } }
        """
        import sqlite3
        if db_path is None:
            db_path = str(Path(__file__).resolve().parent.parent.parent / "spatial_ledger.db")

        results = {}
        try:
            with sqlite3.connect(db_path, timeout=5.0) as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT identifier, device_label, measured_length_m, medium
                    FROM physical_ground_truth
                """)
                for row in cur.fetchall():
                    entry = {
                        "identifier": row[0],
                        "device_label": row[1],
                        "measured_length_m": float(row[2]),
                        "medium": row[3]
                    }
                    results[row[0]] = entry
                    results[row[0].upper()] = entry
                    results[row[0].lower()] = entry

                tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                if "device_registry" in tables:
                    cur.execute("""
                        SELECT mac_address, canonical_name, ground_truth_m, interface_tier
                        FROM device_registry
                        WHERE ground_truth_m IS NOT NULL
                    """)
                    for row in cur.fetchall():
                        mac = row[0]
                        if mac:
                            entry = {
                                "identifier": mac,
                                "device_label": row[1],
                                "measured_length_m": float(row[2]),
                                "medium": row[3]
                            }
                            results[mac] = entry
                            results[mac.upper()] = entry
                            results[mac.lower()] = entry
        except Exception:
            pass
        return results

    @classmethod
    def load_gateway_switchports(cls, db_path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Loads gateway CAM switchport bindings from spatial_ledger.db.
        Returns: { ip: { 'ip': ..., 'switchport': ..., 'port_type': ..., 'device_hint': ... } }
        """
        import sqlite3
        if db_path is None:
            db_path = str(Path(__file__).resolve().parent.parent.parent / "spatial_ledger.db")

        results = {}
        try:
            with sqlite3.connect(db_path, timeout=5.0) as conn:
                cur = conn.cursor()
                cols = [c[1] for c in cur.execute("PRAGMA table_info(gateway_switchports)").fetchall()]
                if "ip_address" in cols and "port_id" in cols:
                    cur.execute("""
                        SELECT ip_address, port_id, connection_type, hostname, mac_address, link_speed_mbps
                        FROM gateway_switchports
                    """)
                    for row in cur.fetchall():
                        ip_val = row[0]
                        port_id = row[1]
                        conn_type = row[2]
                        host_val = row[3]
                        mac_val = row[4]
                        speed_val = row[5]

                        if port_id == "Port 1":
                            port_type = "TRUNK_BRIDGE"
                        elif port_id == "Port 2":
                            port_type = "DIRECT_DROP"
                        elif port_id == "Port 3":
                            port_type = "DIRECT_DROP_100M"
                        elif port_id in ("WLAN", "WLAN_5GHZ", "WLAN_2.4GHZ"):
                            port_type = "WIRELESS_WLAN"
                        else:
                            port_type = "DIRECT_DROP"

                        sw_label = port_id
                        if sw_label == "WLAN":
                            sw_label = "WLAN_5GHZ"

                        entry = {
                            "ip": ip_val,
                            "switchport": sw_label,
                            "port_type": port_type,
                            "device_hint": host_val,
                            "mac": mac_val,
                            "medium": conn_type,
                            "link_speed_mbps": speed_val
                        }
                        if ip_val:
                            results[ip_val] = entry
                        if mac_val:
                            results[mac_val.upper()] = entry
                            results[mac_val.lower()] = entry
                elif "ip" in cols and "switchport" in cols:
                    cur.execute("""
                        SELECT ip, switchport, port_type, device_hint
                        FROM gateway_switchports
                    """)
                    for row in cur.fetchall():
                        results[row[0]] = {
                            "ip": row[0],
                            "switchport": row[1],
                            "port_type": row[2],
                            "device_hint": row[3]
                        }
        except Exception:
            pass
        return results

    @classmethod
    def recalibrate_from_ledger(cls, db_path: Optional[str] = None) -> Dict[str, float]:
        """
        Dynamically recalibrates kernel turnaround baselines against physical ground truth
        and observed RTT convergence records in spatial_ledger.db.
        """
        ground_truth = cls.load_physical_ground_truth(db_path)
        if not ground_truth:
            return dict(RECALIBRATED_KERNEL_BASELINES_US)

        import sqlite3
        if db_path is None:
            db_path = str(Path(__file__).resolve().parent.parent.parent / "spatial_ledger.db")

        nvp = 0.69
        c = 299.792458  # m / us
        switch_delay_us = LOCKED_SWITCH_FABRIC_DELAY_OFFSET_US
        switchports = cls.load_gateway_switchports(db_path)

        updated_baselines = dict(RECALIBRATED_KERNEL_BASELINES_US)
        try:
            with sqlite3.connect(db_path, timeout=5.0) as conn:
                cur = conn.cursor()
                for ident, gt in ground_truth.items():
                    d_m = gt["measured_length_m"]
                    t_flight_us = (2.0 * d_m) / (nvp * c)
                    hop_penalty_us = cls.get_intermediate_hop_penalty_us(ident, switchports)

                    cur.execute("""
                        SELECT min_rtt_us, archetype FROM convergence_ledger
                        WHERE ip = ? OR mac = ?
                        ORDER BY timestamp DESC LIMIT 5
                    """, (ident, ident))
                    rows = cur.fetchall()
                    if rows:
                        avg_min_rtt = sum(r[0] for r in rows) / len(rows)
                        arch = rows[0][1]
                        derived_tk_us = max(50.0, avg_min_rtt - t_flight_us - switch_delay_us - hop_penalty_us)
                        if arch in updated_baselines:
                            updated_baselines[arch] = round(0.7 * updated_baselines[arch] + 0.3 * derived_tk_us, 2)
        except Exception:
            pass

        return updated_baselines

    @classmethod
    def infer_archetype_from_flight_times(
        cls,
        observed_keys: List[str],
        tau_ns_samples: List[float]
    ) -> Dict[str, Any]:
        """
        Evaluates physical kernel latency bounds based on provided nanosecond flight times
        and fuses with Bayesian likelihoods. Zero Redis dependency.
        """
        evidence = list(observed_keys)

        if tau_ns_samples:
            import numpy as np
            min_tau_ns = float(np.min(tau_ns_samples))
            if min_tau_ns < 1000.0:
                evidence.append("kernel_ultra_low_asics")
            elif min_tau_ns < 50000.0:
                evidence.append("kernel_fast_embedded")

        posterior = cls.fuse_evidence(evidence)
        top_arch = max(posterior.items(), key=lambda x: x[1])[0]
        return {
            "archetype": top_arch,
            "confidence": posterior[top_arch],
            "posterior": posterior,
            "raw_tau_ns_samples": tau_ns_samples,
            "min_tau_ns": float(np.min(tau_ns_samples)) if tau_ns_samples else 0.0,
            "calibrated_kernel_turnaround_us": cls.get_calibrated_kernel_turnaround_us(top_arch)
        }

    @classmethod
    def recalibrate_kernel_baselines(
        cls, 
        ground_truth: Dict[str, Dict[str, Any]], 
        switchports: Dict[str, Dict[str, Any]],
        convergence_records: List[Dict[str, Any]]
    ) -> Dict[str, float]:
        """
        Dynamically recalibrates kernel turnaround baselines using injected historical
        convergence telemetry. Zero SQLite dependency.
        """
        if not ground_truth:
            return dict(RECALIBRATED_KERNEL_BASELINES_US)

        nvp = 0.69
        c = 299.792458
        switch_delay_us = LOCKED_SWITCH_FABRIC_DELAY_OFFSET_US
        updated_baselines = dict(RECALIBRATED_KERNEL_BASELINES_US)

        # Map convergence records by identifier for O(1) lookup
        convergence_map = {}
        for record in convergence_records:
            ident = record.get("ip") or record.get("mac")
            if ident:
                convergence_map.setdefault(ident, []).append(record)

        for ident, gt in ground_truth.items():
            d_m = gt["measured_length_m"]
            t_flight_us = (2.0 * d_m) / (nvp * c)
            hop_penalty_us = cls.get_intermediate_hop_penalty_us(ident, switchports)

            records = convergence_map.get(ident, [])
            if records:
                avg_min_rtt = sum(r["min_rtt_us"] for r in records) / len(records)
                arch = records[0]["archetype"]
                derived_tk_us = max(50.0, avg_min_rtt - t_flight_us - switch_delay_us - hop_penalty_us)
                if arch in updated_baselines:
                    updated_baselines[arch] = round(0.7 * updated_baselines[arch] + 0.3 * derived_tk_us, 2)

        return updated_baselines

    @classmethod
    def fuse_evidence(cls, observed_keys: List[str]) -> Dict[str, float]:
        log_posteriors = {arch: math.log(cls.DEFAULT_PRIOR) for arch in cls.ARCHETYPES}

        for ev_key in observed_keys:
            if ev_key not in cls.LIKELIHOOD_TABLE:
                continue
            table = cls.LIKELIHOOD_TABLE[ev_key]
            for arch in cls.ARCHETYPES:
                likelihood = table.get(arch, 0.01)
                log_posteriors[arch] += math.log(max(1e-6, likelihood))

        max_log = max(log_posteriors.values())
        raw_probs = {arch: math.exp(v - max_log) for arch, v in log_posteriors.items()}
        total_mass = sum(raw_probs.values())

        return {arch: prob / total_mass for arch, prob in raw_probs.items()}


def calculate_port_profile(port_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Calculates deterministic delays based on provided port configuration data.
    """
    if not port_data:
        return {
            "port_id": "Unknown",
            "link_speed_mbps": 1000,
            "connection_type": "Ethernet",
            "t_hop_ns": 18.5,
            "is_wireless": False
        }

    port_id = port_data.get("port_id", "Unknown")
    speed = port_data.get("link_speed_mbps", 1000)
    conn_type = port_data.get("connection_type", "Ethernet")
    
    is_wireless = (conn_type == "Wireless") or (port_id == "WLAN")

    if is_wireless:
        t_hop_ns = 0.0
    elif port_id == "Port 1":
        t_hop_ns = 18.5
    else:
        t_hop_ns = 0.0

    return {
        "port_id": port_id,
        "link_speed_mbps": speed if speed else 1000,
        "connection_type": conn_type,
        "t_hop_ns": t_hop_ns,
        "is_wireless": is_wireless
    }

def compute_residual_flight_time(rtt_observed_ns: float, port_data: Dict[str, Any], probe_bytes: int = 64) -> float:
    profile = calculate_port_profile(port_data)

    if profile["is_wireless"]:
        return rtt_observed_ns

    speed_bps = profile["link_speed_mbps"] * 1e6
    t_tx_ns = ((probe_bytes * 8) / speed_bps) * 1e9
    t_deterministic = t_tx_ns + profile["t_hop_ns"]

    return max(0.0, rtt_observed_ns - t_deterministic)

def get_calibrated_hop_parameters(delta_t_us: float) -> dict:
    if delta_t_us <= 90.0:
        return {"tier": "L2_PRIMARY_SWITCH", "hop_delay_ns": 18.5, "effective_rate_mbps": 1000, "sigma_jitter_ns": 2.5}
    return {"tier": "L3_CASCADED_BRIDGE", "hop_delay_ns": 125000.0, "effective_rate_mbps": 100, "sigma_jitter_ns": 25.0}


class BayesianSpatialSolver(SpatialSolverPort):
    def __init__(
        self,
        chassis_matrix: Optional[Dict[str, Any]] = None,
        stp_matrix: Optional[Dict[str, Any]] = None,
        ttl_matrix: Optional[Dict[str, Any]] = None,
        multicast_matrix: Optional[Dict[str, Any]] = None,
        fused_matrix: Optional[Dict[str, Any]] = None,
    ):
        self.fused_matrix = fused_matrix or {}
        self.chassis_matrix = chassis_matrix or self.fused_matrix.get("chassis_matrix", {})
        self.stp_matrix = stp_matrix or self.fused_matrix.get("stp_matrix", {})
        self.ttl_matrix = ttl_matrix or self.fused_matrix.get("ttl_matrix", {})
        self.multicast_matrix = multicast_matrix or self.fused_matrix.get("multicast_matrix", {})
        self.graph = nx.DiGraph()

    def project_topology(self, fused_matrix: Optional[Dict[str, Any]] = None) -> nx.DiGraph:
        """
        Projects fused multi-signal discovery telemetry into a directed topology graph.
        Detects intermediate hops and injects Unmanaged_Switch nodes when multi-hop
        dispersion or elevated STP root path cost is present.
        """
        if fused_matrix is not None:
            self.fused_matrix = fused_matrix

        fused = self.fused_matrix
        chassis_intel = fused.get("chassis_intelligence", self.chassis_matrix)
        stp_intel = fused.get("spanning_tree_intelligence", self.stp_matrix)
        multicast_intel = fused.get("multicast_identity", self.multicast_matrix)
        l3_intel = fused.get("l3_hop_intelligence", self.ttl_matrix)

        graph = nx.DiGraph()
        graph.add_node("Core_Distribution_Switch", type="Core_Distribution_Switch", label="Core_Distribution_Switch")

        # Collect all unique MAC identifiers
        all_macs = set(multicast_intel.keys()) | set(stp_intel.keys()) | set(chassis_intel.keys()) | set(l3_intel.keys())

        # Check if any endpoints are cascaded through an unmanaged switch (hops > 1 or root_path_cost >= 19)
        has_unmanaged = False
        for mac in all_macs:
            hops = l3_intel.get(mac, 1)
            cost = stp_intel.get(mac, {}).get("root_path_cost", 0)
            if hops > 1 or cost >= 19:
                has_unmanaged = True
                break

        if has_unmanaged:
            graph.add_node("Unmanaged_Switch", type="Unmanaged_Switch", ttl_hops=2, label="Unmanaged_Switch")
            graph.add_edge("Core_Distribution_Switch", "Unmanaged_Switch", weight=19.0)

        for mac in sorted(all_macs):
            mc_data = multicast_intel.get(mac, {})
            chassis_data = chassis_intel.get(mac, {})
            stp_data = stp_intel.get(mac, {})
            hops = l3_intel.get(mac, 1)
            cost = stp_data.get("root_path_cost", stp_data.get("pathcost", 1))

            # Identity string resolution
            hostname = chassis_data.get("tlvs", {}).get("hostname")
            if hostname:
                ident_str = hostname
            else:
                ident_str = mc_data.get("identity_string") or mc_data.get("ui_label") or "Generic_Node"

            ui_label = mc_data.get("ui_label", ident_str)

            graph.add_node(
                mac,
                id=mac,
                mac=mac,
                type="Endpoint",
                ttl_hops=hops,
                identity_string=ident_str,
                ui_label=ui_label,
                mdns_services=mc_data.get("mdns_services", []),
                ssdp_headers=mc_data.get("ssdp_headers", []),
                root_path_cost=cost,
            )

            if has_unmanaged and (hops > 1 or cost >= 19):
                graph.add_edge("Unmanaged_Switch", mac, cost=cost, weight=float(cost))
            else:
                graph.add_edge("Core_Distribution_Switch", mac, cost=cost, weight=float(cost))

        self.graph = graph
        return graph