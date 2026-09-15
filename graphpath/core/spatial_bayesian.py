"""
Project AETHERIS - Spatial Bayesian Fusion Engine (Pillar 3)
Calculates exact posterior probability distributions across device archetypes
using discrete likelihood matrices and log-space numerical normalization.
Locks hardware switch fabric delay offsets and recalibrates kernel turnaround
baselines from empirical ground-truth measurements.
"""

import math
import sqlite3
from typing import Dict, List, Any, Optional
from pathlib import Path


# Locked Switch Fabric & ASIC PHY Delay Offset (1.20 µs calibrated hardware baseline)
LOCKED_SWITCH_FABRIC_DELAY_OFFSET_US: float = 1.20
LOCKED_SWITCH_FABRIC_DELAY_OFFSET_SEC: float = 1.20e-6

# Intermediate Switch Hop Penalty (18.5 ns store-and-forward switching latency for intermediate switch hop)
INTERMEDIATE_HOP_PENALTY_NS: float = 18.5
INTERMEDIATE_HOP_PENALTY_US: float = 0.0185
INTERMEDIATE_HOP_PENALTY_SEC: float = 18.5e-9

# Empirically recalibrated kernel turnaround baselines in microseconds
RECALIBRATED_KERNEL_BASELINES_US: Dict[str, float] = {
    "WINDOWS_HOST": 950.0,            # ThinkPad 3.0m & Surface 27.0m anchor calibration
    "LINUX_SERVER": 1100.0,           # Linux kernel TCP softirq turnaround (1.1ms baseline)
    "CCTV_VIDEO": 2180.0,             # Media STB 25.5m & Samsung Smart TV 28.5m
    "NETWORK_INFRASTRUCTURE": 190.0,  # Wi-Fi Extender 27.0m & SFP-to-Gateway Riser 34.0m
    "INDUSTRIAL_OT": 280.0,           # RTOS / PLC fast turnaround
    "VOIP_TELEPHONY": 980.0,          # SIP terminal stack
    "GENERIC_HOST": 1000.0,
}


class BayesianEvidenceFusion:
    ARCHETYPES = [
        "WINDOWS_HOST",
        "VOIP_TELEPHONY",
        "INDUSTRIAL_OT",
        "CCTV_VIDEO",
        "NETWORK_INFRASTRUCTURE",
        "LINUX_SERVER",
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
        """Returns the locked hardware switch fabric & PHY ASIC delay offset in microseconds."""
        return LOCKED_SWITCH_FABRIC_DELAY_OFFSET_US

    @classmethod
    def get_switch_fabric_offset_sec(cls) -> float:
        """Returns the locked hardware switch fabric & PHY ASIC delay offset in seconds."""
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
                # 1. Load from physical_ground_truth
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

                # 2. Unify with device_registry where ground_truth_m is explicitly defined
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

                        # Port type inference
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
    def fuse_evidence(cls, observed_keys: List[str]) -> Dict[str, float]:
        """
        Calculates normalized posterior distribution across archetypes.
        Guarantees mathematically sound probability distribution summing to 1.0.
        """
        log_posteriors = {arch: math.log(cls.DEFAULT_PRIOR) for arch in cls.ARCHETYPES}

        for ev_key in observed_keys:
            if ev_key not in cls.LIKELIHOOD_TABLE:
                continue
            table = cls.LIKELIHOOD_TABLE[ev_key]
            for arch in cls.ARCHETYPES:
                likelihood = table.get(arch, 0.01)
                log_posteriors[arch] += math.log(max(1e-6, likelihood))

        # Log-sum-exp normalization in 64-bit IEEE-754 space
        max_log = max(log_posteriors.values())
        raw_probs = {arch: math.exp(v - max_log) for arch, v in log_posteriors.items()}
        total_mass = sum(raw_probs.values())

        # Exact simplex projection: sum(P) == 1.0 without premature rounding distortion
        return {arch: prob / total_mass for arch, prob in raw_probs.items()}


DB_PATH = Path(__file__).resolve().parent.parent.parent / "spatial_ledger.db"

def get_port_profile(ip_or_mac: str, db_path: Path = DB_PATH) -> Dict[str, Any]:
    """
    Retrieves interface metadata from gateway_switchports to set
    deterministic delays and likelihood priors.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    query = """
        SELECT port_id, link_speed_mbps, connection_type, mac_address 
        FROM gateway_switchports 
        WHERE ip_address = ? OR LOWER(mac_address) = LOWER(?)
        LIMIT 1
    """
    row = cur.execute(query, (ip_or_mac, ip_or_mac)).fetchone()
    conn.close()

    if not row:
        # Fallback default for unknown/unregistered endpoints
        return {
            "port_id": "Unknown",
            "link_speed_mbps": 1000,
            "connection_type": "Ethernet",
            "t_hop_ns": 18.5,
            "is_wireless": False
        }

    port_id, speed, conn_type, mac = row
    is_wireless = (conn_type == "Wireless") or (port_id == "WLAN")

    # Set store-and-forward hop delay
    if is_wireless:
        t_hop_ns = 0.0
    elif port_id == "Port 1":
        t_hop_ns = 18.5  # Calibrated switch bridge delay
    else:
        t_hop_ns = 0.0   # Dedicated direct home runs (Port 2, Port 3)

    return {
        "port_id": port_id,
        "link_speed_mbps": speed if speed else 1000,
        "connection_type": conn_type,
        "t_hop_ns": t_hop_ns,
        "is_wireless": is_wireless
    }

def compute_residual_flight_time(rtt_observed_ns: float, ip_or_mac: str, probe_bytes: int = 64) -> float:
    profile = get_port_profile(ip_or_mac)

    if profile["is_wireless"]:
        # Route to RF path-loss prior
        return rtt_observed_ns

    # Calculate exact serialization delay in nanoseconds
    speed_bps = profile["link_speed_mbps"] * 1e6
    t_tx_ns = ((probe_bytes * 8) / speed_bps) * 1e9

    # Subtract serialization and intermediate bridge hop delay
    t_hop_ns = profile["t_hop_ns"]
    t_deterministic = t_tx_ns + t_hop_ns

    residual_ns = max(0.0, rtt_observed_ns - t_deterministic)
    return residual_ns

def get_calibrated_hop_parameters(ip_address: str, delta_t_us: float) -> dict:
    """
    Differentiates immediate Port 1 switch drops from cascaded
    100Mbps/entertainment switch drops using empirical delta_t slopes.
    """
    # Direct Gigabit drop on Port 1
    if delta_t_us <= 90.0:
        return {
            "tier": "L2_PRIMARY_SWITCH",
            "hop_delay_ns": 18.5,
            "effective_rate_mbps": 1000,
            "sigma_jitter_ns": 2.5
        }
    
    # Cascaded media bridge / 100M segment
    return {
        "tier": "L3_CASCADED_BRIDGE",
        "hop_delay_ns": 125000.0,  # ~125us store-and-forward baseline
        "effective_rate_mbps": 100,
        "sigma_jitter_ns": 25.0
    }