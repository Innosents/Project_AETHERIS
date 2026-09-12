"""
GraphPath Spatial Bayesian Fusion Engine (Pillar 3)
Calculates exact posterior probability distributions across device archetypes
using discrete likelihood matrices and log-space numerical normalization.
"""

import math
from typing import Dict, List


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
            "WINDOWS_HOST": 0.01, "VOIP_TELEPHONY": 0.01, "INDUSTRIAL_OT": 0.98,
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
    }

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