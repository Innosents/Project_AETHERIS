"""
Project AETHERIS - Connectionless LDAP (CLDAP) Infrastructure Adapter
Consumes target IP addresses from 'aetheris:telemetry:l3_active', dispatches
threadpool-isolated UDP port 389 pings, and publishes validated Active Directory
telemetry to 'aetheris:telemetry:ad_intelligence'.
"""

import asyncio
import logging
from typing import Optional

from aetheris.core.ports.l7_cldap_inbound import CldapTelemetryPort
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus
from aetheris.core.parsers.cldap_parser import probe_cldap_endpoint

logger = logging.getLogger("aetheris.adapters.cldap")


class CldapAdapter:
    """
    Decoupled CLDAP Active Directory infrastructure adapter.
    Dispatches non-blocking threadpool UDP queries to target endpoints and publishes
    validated telemetry to 'aetheris:telemetry:ad_intelligence'.
    """

    def __init__(self, event_bus: MemuraiEventBus):
        self.bus = event_bus
        self.consume_queue = "aetheris:telemetry:l3_active"
        self.publish_queue = "aetheris:telemetry:ad_intelligence"

    async def process_target(self, target_ip: str) -> None:
        """
        Dispatches blocking UDP CLDAP ping (timeout bounded to 0.4s) to the threadpool executor,
        validates the response against CldapTelemetryPort, and publishes to the Memurai bus.
        """
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, probe_cldap_endpoint, target_ip, 389, 0.4, "")

        if result and result.get("is_ad_controller"):
            try:
                telemetry = CldapTelemetryPort(**result)
                await self.bus.push_telemetry(self.publish_queue, telemetry.model_dump())
            except Exception as e:
                logger.error(f"CLDAP AD telemetry validation failed for {target_ip}: {e}")

