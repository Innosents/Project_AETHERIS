"""
Project AETHERIS - Fused Spatial Orchestration Layer
Provides unified coordination of L2 SPAN multiplexing and L3 topological sweeps.
"""

import asyncio
import ipaddress
import json
import logging
from typing import Dict, Any, List, NoReturn


from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus
from aetheris.infrastructure.adapters.chassis_probe import ChassisIntelligenceProbe
from aetheris.core.ports.inbound import ChassisIntelligencePort
from aetheris.core.agent import SovereignAgent
from aetheris.infrastructure.adapters.span_tap_adapter import SpanCaptureEngine
from aetheris.core.probers.l2_physical.stp_intelligence import SpanningTreeTelemetryProbe
from aetheris.core.probers.l3_network.multicast_identity import MulticastIdentityProbe
from aetheris.core.probers.l3_network.ttl_interrogator import ActiveTTLInterrogator
from aetheris.core.probers.sanitization import sanitize_prober_payload

logger = logging.getLogger("aetheris.orchestrator")

class AetherisOrchestrator:
    """
    Central execution matrix for the AETHERIS NDR framework.
    Fuses external telemetry adapters with the localized Llama 3.1 SovereignAgent.
    """
    def __init__(self, interface: str):
        self.bus = MemuraiEventBus()
        self.agent = SovereignAgent()
        self.chassis_probe = ChassisIntelligenceProbe(interface=interface, event_bus=self.bus)
        self.intelligence_queue = "aetheris:telemetry:chassis_intelligence"

    async def _consume_chassis_intelligence(self) -> NoReturn:
        """
        Asynchronous consumer loop.
        Extracts validated TLV payloads from Memurai and injects them into the LLM context.
        """
        logger.info(f"Binding consumer to {self.intelligence_queue}")
        while True:
            # BLPOP blocks until telemetry is available, ensuring zero-latency queueing
            queue_name, raw_payload = await self.bus.pop_telemetry(self.intelligence_queue)
            
            try:
                # Re-validate state at the core boundary to ensure bus integrity
                payload_dict = json.loads(raw_payload)
                validated_state = ChassisIntelligencePort(**payload_dict)
                
                # Inject strict JSON into the LLM context window for CVE / topology mapping
                # The agent model is configured strictly for JSON-mode structural outputs
                decision_tensor = await self.agent.evaluate_hardware_state(
                    validated_state.model_dump_json()
                )
                
                logger.info(f"[LLM EVAL] {validated_state.hardware_id} -> Action: {decision_tensor.action_code}")
                
                # Outbound routing logic will bind here (e.g., isolate_port, ignore)
                
            except json.JSONDecodeError:
                logger.critical("Memurai queue corrupted: Payload failed JSON decoding.")
            except Exception as e:
                logger.error(f"Inference loop fault: {e}")

    async def execute_matrix(self) -> None:
        """
        Ignites the intelligence pipeline.
        Arms the Npcap background thread and hands over the primary loop to the consumer.
        """
        self.chassis_probe.start_probe()
        try:
            # Indefinite blocking execution of the cognitive loop
            await self._consume_chassis_intelligence()
        finally:
            self.chassis_probe.stop_probe()
            logger.info("AETHERIS pipeline terminated cleanly.")

if __name__ == "__main__":
    import sys
    target_interface = sys.argv[1] if len(sys.argv) > 1 else "Ethernet"
    
    orchestrator = AetherisOrchestrator(interface=target_interface)
    
    # Enforce strict asyncio scheduling
    try:
        asyncio.run(orchestrator.execute_matrix())
    except KeyboardInterrupt:
        pass

async def _execute_l2_multiplexer(iface: str = "eth0", duration: float = 65.0) -> Dict[str, Any]:
    """
    Executes multiplexed L2 capture across chassis, STP, and multicast identity delegates.
    """
    engine = SpanCaptureEngine(interface=iface)
    chassis_probe = ChassisIntelligenceProbe("", {"span_interface": iface})
    stp_probe = SpanningTreeTelemetryProbe()
    multicast_probe = MulticastIdentityProbe(telemetry_context={"span_interface": iface})

    engine.register_delegate("chassis_intelligence", chassis_probe._frame_callback)
    engine.register_delegate("stp_intelligence", stp_probe._stp_callback)
    engine.register_delegate("multicast_identity", multicast_probe._multicast_callback)

    engine.start()
    try:
        await asyncio.sleep(duration)
    finally:
        engine.stop()

    res = {
        "chassis_intelligence": chassis_probe.chassis_matrix,
        "spanning_tree_intelligence": stp_probe.results,
        "multicast_identity": multicast_probe.identity_matrix,
    }
    return sanitize_prober_payload(res)


async def execute_fused_spatial_sweep(
    target_subnet: str,
    span_interface: str = "eth0",
    duration: float = 65.0,
) -> Dict[str, Any]:
    """
    Coordinates multiplexed L2 telemetry ingestion with active L3 hop interrogation.
    """
    try:
        net = ipaddress.ip_network(target_subnet, strict=False)
        target_ips = [str(ip) for ip in net.hosts()]
    except Exception:
        target_ips = [target_subnet]

    ttl_interrogator = ActiveTTLInterrogator(target_ips=target_ips)
    l2_task = asyncio.create_task(_execute_l2_multiplexer(span_interface, duration))
    l3_task = asyncio.create_task(ttl_interrogator.execute())

    l2_res, l3_res = await asyncio.gather(l2_task, l3_task)

    l3_hop_data = l3_res.get("ttl_matrix", {}) if isinstance(l3_res, dict) else {}

    result = {
        "orchestration_state": "SPATIAL_FUSION_COMPLETE",
        "target_subnet": target_subnet,
        "chassis_intelligence": l2_res.get("chassis_intelligence", {}),
        "spanning_tree_intelligence": l2_res.get("spanning_tree_intelligence", {}),
        "multicast_identity": l2_res.get("multicast_identity", {}),
        "l3_hop_intelligence": l3_hop_data,
    }
    return sanitize_prober_payload(result)
