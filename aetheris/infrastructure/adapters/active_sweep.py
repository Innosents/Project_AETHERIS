import asyncio
import logging
from scapy.all import srp, Ether, ARP
from aetheris.core.ports.l3_inbound import Layer3TelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger('aetheris.adapters.active_sweep')

class ActiveSweepAdapter:
    def __init__(self, interface: str, event_bus: MemuraiEventBus):
        self.interface = interface
        self.bus = event_bus
        self.queue_name = 'aetheris:telemetry:l3_active'

    async def sweep_subnet(self, cidr: str):
        logger.info(f'Initiating L3 spatial sweep on {cidr}')
        # Offload blocking Scapy call to a background thread
        ans, unans = await asyncio.to_thread(
            srp, 
            Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=cidr), 
            iface=self.interface, 
            timeout=2, 
            verbose=False
        )
        
        for snd, rcv in ans:
            try:
                sent_t = getattr(snd, 'sent_time', None) or getattr(snd, 'time', None)
                rcv_t = getattr(rcv, 'time', None)
                if sent_t is not None and rcv_t is not None:
                    delta = float(rcv_t - sent_t)
                    rtt_calc = max(0.0, round(delta * 1000.0, 4))
                else:
                    rtt_calc = 0.0

                telemetry = Layer3TelemetryPort(
                    ip_address=rcv.psrc,
                    hardware_id=rcv.hwsrc,
                    rtt_ms=rtt_calc,
                    open_ports=[]  # TCP sweep delegated to secondary adapter
                )
                await self.bus.push_telemetry(self.queue_name, telemetry.model_dump())
            except Exception as e:
                logger.error(f'Sweep payload validation failed: {e}')

