"""
Project AETHERIS - Adaptive Discovery Orchestrator & Dynamic Protocol Shifting Engine
Ingests multi-signal discovery evidence (MAC OUI, TTL, open ports, passive DPI, banners)
to calculate device class hypotheses, dynamically route prioritized deep probe queues,
and execute Early Termination upon authoritative device identification.
"""

import time
from typing import Dict, Any, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from graphpath.discovery.deep_prober import (
    SmbProber,
    WinRmProber,
    RpcProber,
    RdpProber,
    SipProber,
    WebDeepProber,
    RtspProber,
    SsdpProber,
    ModbusProber,
    MercuryMspProber
)
from graphpath.core.device_classifier import DeviceClassifier
from graphpath.discovery.advanced_spatial_prober import AdvancedSpatialProber

@dataclass
class EvidenceVector:
    """Multi-signal evidence vector collected from passive and active initial sweeps."""
    ip: str
    mac: str = ""
    ttl: int = 0
    open_ports: List[int] = field(default_factory=list)
    banners: Dict[Any, Any] = field(default_factory=dict)
    dpi_data: Dict[str, Any] = field(default_factory=dict)
    subnet_cidr: str = ""
    vendor_hint: str = ""
    hostname_hint: str = ""
    net_flight_us: Optional[float] = None
    estimated_distance_m: Optional[float] = None
    is_trunk: bool = False
    port_id: Optional[str] = None

@dataclass
class HypothesisScore:
    """Probabilistic archetype confidence score."""
    archetype: str
    confidence: float
    evidence_factors: List[str] = field(default_factory=list)


class HypothesisEngine:
    """Calculates device class probabilities from fused multi-signal evidence."""

    ARCHETYPES = [
        "WINDOWS_HOST",
        "VOIP_TELEPHONY",
        "INDUSTRIAL_OT",
        "CCTV_VIDEO",
        "NETWORK_INFRASTRUCTURE",
        "LINUX_SERVER"
    ]

    @classmethod
    def evaluate(cls, ev: EvidenceVector) -> List[HypothesisScore]:
        """Evaluates and ranks all archetype hypotheses against the evidence vector."""
        scores: Dict[str, float] = {arch: 0.05 for arch in cls.ARCHETYPES}
        factors: Dict[str, List[str]] = {arch: [] for arch in cls.ARCHETYPES}

        mac_clean = ev.mac.replace(":", "").replace("-", "").upper()[:6] if ev.mac else ""
        oui_info = DeviceClassifier.OUI_DB.get(mac_clean, {})
        oui_vendor = oui_info.get("vendor", "").lower()
        oui_type = oui_info.get("type", "").lower()

        ports_set = set(ev.open_ports)
        all_banners = " ".join(str(v) for v in ev.banners.values()).lower()

        # 1. Evaluate WINDOWS_HOST
        if 100 <= ev.ttl <= 130:
            scores["WINDOWS_HOST"] += 0.35
            factors["WINDOWS_HOST"].append(f"ICMP TTL={ev.ttl} (Windows default 128)")
        if any(p in ports_set for p in [135, 445, 5985, 5986, 3389]):
            matched_ports = [p for p in [135, 445, 5985, 5986, 3389] if p in ports_set]
            scores["WINDOWS_HOST"] += 0.45
            factors["WINDOWS_HOST"].append(f"Windows RPC/SMB/WinRM/RDP ports open: {matched_ports}")
        if "microsoft" in oui_vendor or "thinkcentre" in all_banners or "windows" in all_banners:
            scores["WINDOWS_HOST"] += 0.3
            factors["WINDOWS_HOST"].append("Windows OUI/Banner signature detected")

        # 2. Evaluate VOIP_TELEPHONY
        if any(p in ports_set for p in [5060, 5061]) or "sip" in all_banners:
            scores["VOIP_TELEPHONY"] += 0.5
            factors["VOIP_TELEPHONY"].append("SIP port 5060/5061 or SIP banner detected")
        if oui_type in ("voip_phone", "voip_pbx") or any(k in oui_vendor for k in ["grandstream", "yealink", "polycom", "mitel", "snom", "fanvil", "asterisk"]):
            scores["VOIP_TELEPHONY"] += 0.45
            factors["VOIP_TELEPHONY"].append(f"Telephony Hardware OUI: {oui_vendor}")
        if ev.dpi_data.get("protocol") == "SIP" or "gxp" in all_banners:
            scores["VOIP_TELEPHONY"] += 0.4
            factors["VOIP_TELEPHONY"].append("SIP DPI / User-Agent signature")

        # 3. Evaluate INDUSTRIAL_OT
        if any(p in ports_set for p in [502, 102, 44818, 3001, 23001, 20502, 20102]):
            ot_ports = [p for p in [502, 102, 44818, 3001, 23001, 20502, 20102] if p in ports_set]
            scores["INDUSTRIAL_OT"] += 0.65
            factors["INDUSTRIAL_OT"].append(f"Industrial ICS/SCADA ports open: {ot_ports}")
        if any(k in oui_vendor for k in ["rockwell", "allen-bradley", "siemens", "schneider", "moxa", "mercury", "wago"]):
            scores["INDUSTRIAL_OT"] += 0.4
            factors["INDUSTRIAL_OT"].append(f"Industrial Automation OUI: {oui_vendor}")
        if "modbus" in all_banners or "s7" in all_banners:
            scores["INDUSTRIAL_OT"] += 0.35
            factors["INDUSTRIAL_OT"].append("Modbus/S7comm protocol banner")

        # 4. Evaluate CCTV_VIDEO
        if any(p in ports_set for p in [554, 8554, 37777, 38880, 38881, 28082, 28083, 25554]):
            cam_ports = [p for p in [554, 8554, 37777, 38880, 38881, 28082, 28083, 25554] if p in ports_set]
            scores["CCTV_VIDEO"] += 0.55
            factors["CCTV_VIDEO"].append(f"RTSP / Video Streaming / NVR ports open: {cam_ports}")
        if oui_type in ("camera", "nvr") or any(k in oui_vendor for k in ["hikvision", "dahua", "axis", "flir", "avigilon", "tiandy", "hanwha"]):
            scores["CCTV_VIDEO"] += 0.45
            factors["CCTV_VIDEO"].append(f"CCTV Surveillance OUI: {oui_vendor}")
        if "onvif" in all_banners or "rtsp" in all_banners:
            scores["CCTV_VIDEO"] += 0.35
            factors["CCTV_VIDEO"].append("ONVIF/RTSP streaming banner")

        # 5. Evaluate NETWORK_INFRASTRUCTURE
        if 200 <= ev.ttl <= 255:
            scores["NETWORK_INFRASTRUCTURE"] += 0.35
            factors["NETWORK_INFRASTRUCTURE"].append(f"ICMP TTL={ev.ttl} (Network appliance default 255)")
        if 161 in ports_set or (22 in ports_set and 80 in ports_set and len(ports_set) <= 4):
            scores["NETWORK_INFRASTRUCTURE"] += 0.35
            factors["NETWORK_INFRASTRUCTURE"].append("SNMP port 161 or Switch SSH/HTTP management profile")
        if any(k in oui_vendor for k in ["cisco", "aruba", "juniper", "ubiquiti", "mikrotik", "netgear", "tp-link", "fortinet"]):
            scores["NETWORK_INFRASTRUCTURE"] += 0.35
            factors["NETWORK_INFRASTRUCTURE"].append(f"Network Infrastructure OUI: {oui_vendor}")

        # 6. Evaluate LINUX_SERVER
        if 50 <= ev.ttl <= 68 and 22 in ports_set:
            scores["LINUX_SERVER"] += 0.35
            factors["LINUX_SERVER"].append(f"ICMP TTL={ev.ttl} with SSH Port 22")
        if any(p in ports_set for p in [3306, 5432, 27017, 6379, 8080, 9000]):
            scores["LINUX_SERVER"] += 0.3
            factors["LINUX_SERVER"].append("Enterprise Database / Server Port open")

        # Normalize and sort
        ranked = []
        for arch in cls.ARCHETYPES:
            confidence = min(1.0, scores[arch])
            ranked.append(HypothesisScore(
                archetype=arch,
                confidence=round(confidence, 3),
                evidence_factors=factors[arch]
            ))

        ranked.sort(key=lambda x: x.confidence, reverse=True)
        return ranked


class AdaptiveProbeRouter:
    """Builds a prioritized deep probe execution plan and pruning list."""

    @classmethod
    def build_plan(
        cls,
        hypothesis: HypothesisScore,
        open_ports: List[int],
        net_flight_us: Optional[float] = None,
        estimated_distance_m: Optional[float] = None,
        is_trunk: bool = False,
        return_meta: bool = False,
    ) -> Union[Tuple[List[str], List[str]], Tuple[List[str], List[str], Dict[str, Any]]]:
        """
        Returns: (prioritized_probe_queue, pruned_probes_list) or (queue, pruned, spatial_meta)
        """
        ports_set = set(open_ports)
        queue: List[str] = []
        pruned: List[str] = []

        arch = hypothesis.archetype

        if arch == "WINDOWS_HOST":
            # Priority: WinRM -> RPC -> SMB -> RDP
            if any(p in ports_set for p in [5985, 5986, 25985]): queue.append("winrm")
            if any(p in ports_set for p in [135, 20135]): queue.append("rpc")
            if any(p in ports_set for p in [445, 139, 20445]): queue.append("smb")
            if 3389 in ports_set: queue.append("rdp")
            pruned.extend(["modbus", "cip", "s7", "onvif", "rtsp", "sip", "snmp_crawl"])

        elif arch == "VOIP_TELEPHONY":
            # Priority: SIP OPTIONS -> HTTP Phone Web Admin
            if any(p in ports_set for p in [5060, 5061]): queue.append("sip")
            if any(p in ports_set for p in [80, 443, 8080]): queue.append("http_web")
            pruned.extend(["smb", "rpc", "winrm", "rdp", "modbus", "s7", "cip", "database"])

        elif arch == "INDUSTRIAL_OT":
            # Priority: Modbus MEI-14 -> CIP Identity -> S7comm SZL
            if any(p in ports_set for p in [502, 20502, 20504, 20505, 20506, 20507]): queue.append("modbus")
            if any(p in ports_set for p in [44818, 24818]): queue.append("cip")
            if any(p in ports_set for p in [102, 20102]): queue.append("s7")
            if any(p in ports_set for p in [3001, 23001]): queue.append("msp")
            pruned.extend(["smb", "winrm", "rdp", "sip", "heavy_web_crawl", "ssh_bruteforce"])

        elif arch == "CCTV_VIDEO":
            # Priority: ONVIF SOAP -> RTSP Server
            if any(p in ports_set for p in [80, 443, 8080, 28082, 28092]): queue.append("onvif")
            if any(p in ports_set for p in [554, 8554, 25554, 25555, 37777]): queue.append("rtsp")
            pruned.extend(["smb", "rpc", "winrm", "rdp", "modbus", "s7", "database"])

        elif arch == "NETWORK_INFRASTRUCTURE":
            # Priority: SNMP LLDP/CDP MIBs -> TLS / HTTP Admin
            if 161 in ports_set: queue.append("snmp")
            if any(p in ports_set for p in [443, 8443, 28080, 28081]): queue.append("tls")
            if any(p in ports_set for p in [80, 8080]): queue.append("http_web")
            pruned.extend(["modbus", "s7", "cip", "rtsp", "winrm"])

        else:
            # General / Linux Server / Media & IoT Endpoints
            if any(p in ports_set for p in [443, 8443]): queue.append("tls")
            if any(p in ports_set for p in [80, 8080, 8000]): queue.append("http_web")
            if 1900 in ports_set: queue.append("ssdp")
            if any(p in ports_set for p in [445, 139]): queue.append("smb")
            if 3389 in ports_set: queue.append("rdp")

        # Global SSDP inclusion if port 1900 is explicitly open and not yet in queue
        if 1900 in ports_set and "ssdp" not in queue:
            queue.append("ssdp")

        # Spatial Constraint Boundary Evaluation
        spatial_eval = AdvancedSpatialProber.evaluate_spatial_pruning_boundary(
            net_flight_us=net_flight_us,
            estimated_distance_m=estimated_distance_m,
            is_trunk=is_trunk,
        )

        spatial_meta: Dict[str, Any] = {
            "spatial_state": spatial_eval["spatial_state"],
            "bypass_copper_limits": spatial_eval["bypass_copper_limits"],
            "prune_high_throughput": spatial_eval["prune_high_throughput"],
            "reason": spatial_eval["reason"],
            "net_flight_us": net_flight_us,
            "estimated_distance_m": estimated_distance_m,
            "is_trunk": is_trunk,
            "spatial_pruned_probes": [],
        }

        # Enforce spatial constraint pruning against deep protocol probes
        if spatial_eval["prune_high_throughput"]:
            # Restrict RTSP streaming and high-throughput web sweeps on out-of-spec copper (>110m)
            probes_to_prune = ["rtsp", "http_web", "heavy_web_crawl"]
            for p in probes_to_prune:
                if p in queue:
                    queue.remove(p)
                    pruned.append(p)
                    spatial_meta["spatial_pruned_probes"].append(p)

        if return_meta:
            return queue, pruned, spatial_meta
        return queue, pruned


class SubnetAdaptiveMemory:
    """Tracks subnet-level archetype density to enable automated specialized modes (e.g. OT Safe Mode)."""

    def __init__(self):
        self.subnet_profiles: Dict[str, Dict[str, int]] = {}

    def record_host_archetype(self, subnet_cidr: str, archetype: str):
        """Increments archetype counters for the subnet."""
        if not subnet_cidr:
            return
        if subnet_cidr not in self.subnet_profiles:
            self.subnet_profiles[subnet_cidr] = {}
        self.subnet_profiles[subnet_cidr][archetype] = self.subnet_profiles[subnet_cidr].get(archetype, 0) + 1

    def is_ot_dense_subnet(self, subnet_cidr: str) -> bool:
        """Determines if a subnet is predominantly Industrial OT equipment."""
        if subnet_cidr not in self.subnet_profiles:
            return False
        profile = self.subnet_profiles[subnet_cidr]
        ot_count = profile.get("INDUSTRIAL_OT", 0)
        total = sum(profile.values())
        return total >= 3 and (ot_count / total) >= 0.4


class AdaptiveDiscoveryOrchestrator:
    """
    Central adaptive discovery engine that orchestrates dynamic protocol shifting
    and early termination across network nodes.
    """

    def __init__(self):
        self.memory = SubnetAdaptiveMemory()
        self.metrics = {
            "total_hosts_evaluated": 0,
            "probes_executed": 0,
            "probes_pruned": 0,
            "early_terminations": 0
        }

    def execute_adaptive_sweep(self, ev: EvidenceVector, timeout: float = 0.6) -> Dict[str, Any]:
        """
        Executes an adaptive, dynamically shifted secondary discovery pass for a host.
        Stops early as soon as authoritative identity is acquired.
        """
        start_time = time.time()
        self.metrics["total_hosts_evaluated"] += 1

        # 1. Multi-Signal Evidence Fusion & Hypothesis Evaluation
        ranked_hypotheses = HypothesisEngine.evaluate(ev)
        top_hypothesis = ranked_hypotheses[0] if ranked_hypotheses else HypothesisScore("LINUX_SERVER", 0.1)

        # Record into Subnet Memory
        if ev.subnet_cidr:
            self.memory.record_host_archetype(ev.subnet_cidr, top_hypothesis.archetype)

        # 2. Build Targeted Probe Queue and Pruning List
        probe_queue, pruned_list, spatial_meta = AdaptiveProbeRouter.build_plan(
            top_hypothesis,
            ev.open_ports,
            net_flight_us=ev.net_flight_us,
            estimated_distance_m=ev.estimated_distance_m,
            is_trunk=ev.is_trunk,
            return_meta=True,
        )
        self.metrics["probes_pruned"] += len(pruned_list)

        results: Dict[str, Any] = {
            "ip": ev.ip,
            "top_hypothesis": top_hypothesis.archetype,
            "hypothesis_confidence": top_hypothesis.confidence,
            "evidence_factors": top_hypothesis.evidence_factors,
            "spatial_state": spatial_meta["spatial_state"],
            "spatial_pruning": spatial_meta,
            "probes_executed": [],
            "probes_pruned": pruned_list,
            "early_terminated": False,
            "deep_probes": {},
            "banners": {},
            "metadata": {}
        }

        # 3. Execute Prioritized Probes in Sequence with Early Termination
        for probe_name in probe_queue:
            results["probes_executed"].append(probe_name)
            self.metrics["probes_executed"] += 1
            probe_res: Dict[str, Any] = {}

            if probe_name == "winrm":
                winrm_port = next((p for p in [5985, 5986, 25985] if p in ev.open_ports), 5985)
                probe_res = WinRmProber.probe_winrm(ev.ip, winrm_port, timeout=timeout)
            elif probe_name == "rpc":
                rpc_port = 135 if 135 in ev.open_ports else 20135
                probe_res = RpcProber.probe_rpc(ev.ip, rpc_port, timeout=timeout)
            elif probe_name == "smb":
                smb_port = 445 if 445 in ev.open_ports else (139 if 139 in ev.open_ports else 20445)
                probe_res = SmbProber.probe_smb(ev.ip, smb_port, timeout=timeout)
            elif probe_name == "rdp":
                probe_res = RdpProber.probe_rdp(ev.ip, 3389, timeout=timeout)
            elif probe_name == "sip":
                sip_port = 5060 if 5060 in ev.open_ports else 5061
                probe_res = SipProber.probe_sip(ev.ip, sip_port, timeout=timeout)
            elif probe_name == "onvif":
                onvif_port = next((p for p in [80, 443, 8080, 28082, 28092] if p in ev.open_ports), 80)
                probe_res = WebDeepProber.probe_onvif_soap(ev.ip, onvif_port, timeout=timeout)
            elif probe_name == "rtsp":
                rtsp_port = next((p for p in [554, 8554, 25554, 25555, 37777] if p in ev.open_ports), 554)
                probe_res = RtspProber.probe_rtsp(ev.ip, rtsp_port, timeout=timeout)
            elif probe_name == "tls":
                tls_port = next((p for p in [443, 8443, 28080, 28081] if p in ev.open_ports), 443)
                probe_res = WebDeepProber.inspect_tls_cert(ev.ip, tls_port, timeout=timeout)
            elif probe_name == "http_web":
                http_port = next((p for p in [80, 8080, 8000] if p in ev.open_ports), 80)
                probe_res = WebDeepProber.probe_upnp_description(ev.ip, http_port, timeout=timeout)
            elif probe_name == "ssdp":
                ssdp_port = 1900 if 1900 in ev.open_ports else 1900
                probe_res = SsdpProber.probe_ssdp(ev.ip, ssdp_port, timeout=timeout)
            elif probe_name == "msp":
                msp_port = next((p for p in [3001, 23001] if p in ev.open_ports), 3001)
                probe_res = MercuryMspProber.probe_msp(ev.ip, msp_port, timeout=timeout)
                if probe_res.get("peripherals"):
                    try:
                        from discovery.mercury_spatial_resolver import MercurySpatialResolver
                        resolved_periphs = []
                        for periph in probe_res["peripherals"]:
                            spatial_telemetry = MercurySpatialResolver.resolve_peripheral_spatial_telemetry(
                                controller_id=f"mercury_{ev.ip}",
                                peripheral=periph,
                                source_voltage=12.0
                            )
                            periph["spatial_metrics"] = spatial_telemetry
                            resolved_periphs.append(periph)
                        probe_res["peripherals"] = resolved_periphs
                    except Exception:
                        pass
            elif probe_name == "modbus":
                modbus_port = next((p for p in [502, 20502, 20504] if p in ev.open_ports), 502)
                probe_res = ModbusProber.probe_modbus(ev.ip, modbus_port, timeout=timeout)

            if probe_res:
                results["deep_probes"][probe_name] = probe_res

                # Surface authoritative fields
                for k in ["hostname", "domain", "vendor", "model", "serial_number", "os_version", "type"]:
                    if probe_res.get(k) and not results.get(k):
                        results[k] = probe_res[k]

                # Format banners
                if probe_name == "winrm" and probe_res.get("os_version"):
                    results["banners"]["winrm"] = f"WinRM: {probe_res.get('os_version')} | Host: {probe_res.get('hostname', '')}"
                elif probe_name == "rpc" and probe_res.get("interfaces"):
                    results["metadata"]["multihomed_interfaces"] = probe_res["interfaces"]
                    results["banners"]["rpc_interfaces"] = "Multi-homed IPs: " + ", ".join(probe_res["interfaces"])
                elif probe_name == "smb" and probe_res.get("os_version"):
                    results["banners"]["smb_os"] = f"{probe_res.get('os_version')} | Domain: {probe_res.get('domain', 'WORKGROUP')}"
                elif probe_name == "sip" and probe_res.get("sip_user_agent"):
                    results["banners"]["sip_agent"] = probe_res["sip_user_agent"]
                elif probe_name == "onvif" and probe_res.get("model"):
                    results["banners"]["onvif"] = f"ONVIF Camera: {probe_res.get('vendor', '')} {probe_res.get('model', '')} (FW: {probe_res.get('firmware', '')})"
                elif probe_name == "rtsp" and probe_res.get("rtsp_server"):
                    results["banners"]["rtsp"] = f"RTSP Stream: {probe_res['rtsp_server']}"
                elif probe_name == "ssdp":
                    if probe_res.get("model"):
                        results["banners"]["ssdp"] = f"UPnP/SSDP: {probe_res.get('vendor', '')} {probe_res.get('model', '')} | Name: {probe_res.get('friendly_name', '')}"
                    elif probe_res.get("ssdp_server"):
                        results["banners"]["ssdp"] = f"SSDP: {probe_res['ssdp_server']}"
                elif probe_name == "msp" and probe_res.get("model"):
                    periph_count = len(probe_res.get("peripherals", []))
                    results["banners"]["msp"] = f"{probe_res.get('model', 'Mercury Controller')} ({probe_res.get('status', 'ONLINE')}) | {periph_count} Peripherals"
                    if probe_res.get("peripherals"):
                        results["metadata"]["peripherals"] = probe_res["peripherals"]
                elif probe_name == "modbus" and probe_res.get("model"):
                    results["banners"]["modbus"] = f"Modbus PLC: {probe_res.get('vendor', '')} {probe_res.get('model', '')}"

                # Early Termination Rule: If OS version, Hostname, and Domain (or Camera Serial / Phone Model) are locked
                has_full_identity = (
                    (results.get("os_version") and results.get("hostname")) or
                    (results.get("serial_number") and results.get("model")) or
                    (results.get("sip_user_agent"))
                )
                if has_full_identity:
                    results["early_terminated"] = True
                    self.metrics["early_terminations"] += 1
                    break

        results["execution_duration_ms"] = round((time.time() - start_time) * 1000, 2)
        return results

