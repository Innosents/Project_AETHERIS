"""
AnchorGuard: Physical Conductor Verification and Anchor Qualification Engine.

Enforces strict medium-type filtering, Layer 1 switchport CAM binding,
and non-stochastic empirical jitter constraints to prevent RF multi-path
and CSMA/CA delay variance from contaminating the AETHERIS WLS spatial solver.
"""
import re
from typing import Dict, Any, Optional, Set, Tuple

from aetheris.core.ports.spatial_anchor_port import (
    AnchorCandidateEvaluation,
    SpatialLedgerPort,
    TargetReadinessResult,
)


class AnchorGuard:
    """
    Evaluates node candidates for spatial anchor status. Disqualifies any candidate
    relying on wireless (802.11 / RF / AirLink) media, roaming profiles, or unbound switchports.
    """

    VALID_CONDUCTOR_TOKENS: Tuple[str, ...] = (
        "COPPER",
        "CAT5",
        "CAT5E",
        "CAT6",
        "CAT6A",
        "CAT7",
        "CAT8",
        "FIBER",
        "SMF",
        "MMF",
        "TWISTED_PAIR",
    )

    WIRELESS_TOKENS: Tuple[str, ...] = (
        "WLAN",
        "802.11",
        "AIRLINK",
        "WIFI",
        "WIRELESS",
        "RF",
        "BLUETOOTH",
        "RADIO",
        "MICROWAVE",
    )

    WIRELESS_ARCHETYPES: Set[str] = {
        "MOBILE",
        "MOBILE_IOS",
        "MOBILE_ANDROID",
        "TABLET",
        "WLAN_AP",
        "WLAN_BRIDGE",
        "WLAN_CLIENT",
        "ACCESS_POINT",
        "HOTSPOT",
    }

    MAX_ANCHOR_JITTER_US: float = 25.0

    @classmethod
    def is_physical_conductor(cls, medium: Optional[str]) -> bool:
        """Returns True if medium is strictly a deterministic physical conductor."""
        if not medium or not isinstance(medium, str):
            return False
        med_upper = medium.upper()
        if any(w in med_upper for w in cls.WIRELESS_TOKENS):
            return False
        return any(c in med_upper for c in cls.VALID_CONDUCTOR_TOKENS)

    @classmethod
    def is_wireless_medium(cls, medium: Optional[str]) -> bool:
        """Returns True if medium exhibits RF / wireless characteristics."""
        if not medium or not isinstance(medium, str):
            return False
        med_upper = medium.upper()
        words = set(re.findall(r"[A-Za-z0-9.]+", med_upper))
        if bool(words & cls.WIRELESS_ARCHETYPES) or "RF" in words:
            return True
        long_tokens = [t for t in cls.WIRELESS_TOKENS if len(t) >= 4]
        return any(w in med_upper for w in long_tokens)

    @classmethod
    def evaluate_anchor_candidate(
        cls,
        candidate: Dict[str, Any],
    ) -> AnchorCandidateEvaluation:
        """
        Executes a 4-tier qualification evaluation on an anchor candidate.
        
        Returns a normalized dictionary:
          - is_anchor: bool (True only if all 4 tiers pass)
          - anchor_trust_state: str (TRUSTED_PHYSICAL_ANCHOR or failure state)
          - disqualification_reason: Optional[str]
          - edge_type: str (ETHERNET_ANCHOR, ETHERNET_LINK, or WIRELESS_AIRLINK)
          - medium: str
          - port_verified: bool
        """
        requested_anchor = bool(candidate.get("is_anchor", False))
        medium_raw = str(candidate.get("medium") or candidate.get("edge_medium") or "").strip()
        edge_type_raw = str(candidate.get("edge_type") or "").strip()
        switchport = str(candidate.get("switchport") or candidate.get("port") or "").strip()
        dev_type = str(candidate.get("device_type") or candidate.get("type") or "").strip().upper()
        archetype = str(candidate.get("archetype") or "").strip().upper()
        hint = str(candidate.get("device_hint") or candidate.get("hostname") or "").strip().upper()

        jitter_us = float(candidate.get("jitter_us") or 0.0)
        if not jitter_us and candidate.get("jitter_ns"):
            jitter_us = float(candidate["jitter_ns"]) / 1000.0

        all_desc = f"{dev_type} {archetype} {hint}"
        desc_words = set(re.findall(r"[A-Za-z0-9.]+", all_desc))
        long_tokens = [t for t in cls.WIRELESS_TOKENS if len(t) >= 4]

        has_explicit_physical_medium = cls.is_physical_conductor(medium_raw)

        is_wireless = False
        if not has_explicit_physical_medium:
            is_wireless = (
                cls.is_wireless_medium(medium_raw)
                or edge_type_raw in ("WIRELESS_AIRLINK", "WIRELESS_LINK")
                or bool(desc_words & cls.WIRELESS_ARCHETYPES)
                or "RF" in desc_words
                or any(t in all_desc for t in long_tokens)
            )

        port_verified = bool(
            switchport
            and switchport.lower() not in ("unknown", "unbound", "none", "n/a", "")
            and not switchport.lower().startswith("wlan")
            and not switchport.lower().startswith("airlink")
        )

        normalized_medium = medium_raw
        if not normalized_medium or is_wireless:
            normalized_medium = "WLAN (802.11 AirLink)" if is_wireless else "Copper (Cat5e/Cat6 Drop)"

        wireless_edge_type = edge_type_raw if edge_type_raw in ("WIRELESS_LINK", "WIRELESS_AIRLINK") else "WIRELESS_AIRLINK"
        ethernet_edge_type = edge_type_raw if edge_type_raw in ("ETHERNET_LINK", "ETHERNET_ANCHOR") else "ETHERNET_LINK"

        if not requested_anchor:
            return AnchorCandidateEvaluation(
                is_anchor=False,
                anchor_trust_state="UNQUALIFIED_ENDPOINT",
                disqualification_reason=None,
                edge_type=wireless_edge_type if is_wireless else ethernet_edge_type,
                medium=normalized_medium,
                port_verified=port_verified,
            )

        # Candidate claimed is_anchor = True; enforce 4-tier validation
        # Tier 1: Conductor Whitelist & Wireless Blacklist
        if is_wireless or not cls.is_physical_conductor(normalized_medium):
            return AnchorCandidateEvaluation(
                is_anchor=False,
                anchor_trust_state="DISQUALIFIED_WIRELESS_MEDIUM",
                disqualification_reason=(
                    f"Candidate medium '{normalized_medium}' exhibits RF/AirLink characteristics. "
                    "Wireless links induce non-deterministic multipath and CSMA/CA delay jitter, "
                    "corrupting WLS baseline calibration."
                ),
                edge_type=wireless_edge_type,
                medium=normalized_medium,
                port_verified=port_verified,
            )

       # Tier 2: Stationary Device Archetype & Bridge/Extender Filter
        BRIDGE_AP_ARCHETYPES = {
            "WLAN_AP", "ACCESS_POINT", "WLAN_BRIDGE", "ANDROID_WLAN_BRIDGE",
            "EXTENDER", "REPEATER", "MOBILE", "TABLET", "WIFI_PLUS"
        }

        # Check against passed archetype, dev_type, and tokenized descriptions
        target_archetype = (archetype or dev_type or "").upper()
        # locals fallback handled gracefully
        h_hint = candidate.get('device_hint', '')
        h_host = candidate.get('hostname', '')
        ident_str = f"{dev_type} {archetype} {h_hint} {h_host}".upper()

        is_bridge = (
            bool(desc_words & cls.WIRELESS_ARCHETYPES)
            or target_archetype in cls.WIRELESS_ARCHETYPES
            or target_archetype in BRIDGE_AP_ARCHETYPES
            or any(token in ident_str for token in ["WIFI_PLUS", "EXTENDER", "REPEATER", "AIRLINK"])
        )

        if is_bridge and not has_explicit_physical_medium:
            return AnchorCandidateEvaluation(
                is_anchor=False,
                anchor_trust_state="DISQUALIFIED_BRIDGE_OR_AP",
                disqualification_reason=(
                    f"Candidate '{archetype or dev_type}' acts as an active RF Access Point, "
                    "extender, or L2 bridge. Bridges induce store-and-forward queuing and "
                    "dynamic association variance, violating WLS baseline determinism."
                ),
                edge_type=wireless_edge_type,
                medium=normalized_medium,
                port_verified=port_verified,
            )
        
        # Tier 3: Chassis Switchport CAM Binding
        if not port_verified:
            return AnchorCandidateEvaluation(
                is_anchor=False,
                anchor_trust_state="DISQUALIFIED_UNBOUND_PORT",
                disqualification_reason=(
                    f"Candidate switchport '{switchport}' is unbound or unverified in gateway CAM/FDB. "
                    "Physical anchors must have a verified chassis pin binding."
                ),
                edge_type="ETHERNET_LINK",
                medium=normalized_medium,
                port_verified=False,
            )

        # Tier 4: Empirical Jitter Variance Guard
        if jitter_us > cls.MAX_ANCHOR_JITTER_US:
            return AnchorCandidateEvaluation(
                is_anchor=False,
                anchor_trust_state="DISQUALIFIED_HIGH_JITTER",
                disqualification_reason=(
                    f"Empirical jitter ({jitter_us:.2f}µs) exceeds anchor threshold ({cls.MAX_ANCHOR_JITTER_US}µs). "
                    "Potential buffer bloat or link instability detected."
                ),
                edge_type="ETHERNET_LINK",
                medium=normalized_medium,
                port_verified=True,
            )

        # All 4 tiers passed
        return AnchorCandidateEvaluation(
            is_anchor=True,
            anchor_trust_state="TRUSTED_PHYSICAL_ANCHOR",
            disqualification_reason=None,
            edge_type="ETHERNET_ANCHOR",
            medium=normalized_medium,
            port_verified=True,
        )

    @classmethod
    def validate_target_readiness(
        cls,
        target_ip: str,
        ledger: Optional[SpatialLedgerPort] = None,
        max_tau_flight_ns: float = 1000.0,
        min_z0_ohms: float = 85.0,
        max_z0_ohms: float = 115.0,
        nvp: float = 0.69,
    ) -> TargetReadinessResult:
        """
        Validates target readiness for deep telemetry interrogation by verifying
        calibrated tau_flight and dynamic transmission line impedance (Z_0)
        metrics directly from the Redis spatial ledger.
        """
        import numpy as np

        if not ledger:
            return TargetReadinessResult(
                is_ready=False,
                readiness_state="LEDGER_UNAVAILABLE",
                target_ip=target_ip,
                reason="Redis telemetry ledger unavailable for physical metric verification.",
                tau_flight_ns=None,
                z0_ohms=None,
            )

        try:
            flight_times = ledger.get_raw_nanosecond_flight_times(target_ip)
        except Exception as e:
            return TargetReadinessResult(
                is_ready=False,
                readiness_state="QUERY_ERROR",
                target_ip=target_ip,
                reason=f"Ledger query error for {target_ip}: {e}",
                tau_flight_ns=None,
                z0_ohms=None,
            )

        if not flight_times or len(flight_times) == 0:
            return TargetReadinessResult(
                is_ready=False,
                readiness_state="READINESS_PENDING_CALIBRATION",
                target_ip=target_ip,
                reason=f"Target {target_ip} has no calibrated RFC 7323 tau_flight metrics in Redis ledger.",
                tau_flight_ns=None,
                z0_ohms=None,
            )

        # Filter out negative or extreme artifacts
        valid_samples = [float(t) for t in flight_times if t > 0]
        if not valid_samples:
            return TargetReadinessResult(
                is_ready=False,
                readiness_state="INVALID_TEMPORAL_SAMPLES",
                target_ip=target_ip,
                reason="All flight time samples in ledger are non-positive.",
                tau_flight_ns=None,
                z0_ohms=None,
            )

        tau_flight_ns = float(np.percentile(valid_samples, 10))
        jitter_ns = float(np.ptp(valid_samples)) if len(valid_samples) > 1 else 0.0

        if tau_flight_ns > max_tau_flight_ns:
            return TargetReadinessResult(
                is_ready=False,
                readiness_state="DISQUALIFIED_EXCESSIVE_LATENCY",
                target_ip=target_ip,
                reason=f"Tau flight time ({tau_flight_ns:.1f}ns) exceeds threshold ({max_tau_flight_ns:.1f}ns).",
                tau_flight_ns=round(tau_flight_ns, 2),
                z0_ohms=None,
            )

        # Derive dynamic transmission line impedance
        z0_metrics = ledger.calculate_dynamic_line_impedance(
            tau_flight_ns=tau_flight_ns,
            jitter_ns=jitter_ns,
            nvp=nvp
        )
        z0_ohms = z0_metrics["z0_ohms"]
        distance_m = z0_metrics["distance_m"]

        if not (min_z0_ohms <= z0_ohms <= max_z0_ohms):
            return TargetReadinessResult(
                is_ready=False,
                readiness_state="DISQUALIFIED_IMPEDANCE_OUT_OF_SPEC",
                target_ip=target_ip,
                reason=f"Line impedance ({z0_ohms:.2f} ohms) outside transmission spec [{min_z0_ohms}, {max_z0_ohms}].",
                tau_flight_ns=round(tau_flight_ns, 2),
                z0_ohms=round(z0_ohms, 2),
                distance_m=round(distance_m, 2),
            )

        return TargetReadinessResult(
            is_ready=True,
            readiness_state="QUALIFIED_PHYSICAL_TARGET",
            target_ip=target_ip,
            reason=None,
            tau_flight_ns=round(tau_flight_ns, 2),
            z0_ohms=round(z0_ohms, 2),
            distance_m=round(distance_m, 2),
            jitter_ns=round(jitter_ns, 2),
            is_within_spec=True,
        )

