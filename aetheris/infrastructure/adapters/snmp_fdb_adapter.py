"""
Project AETHERIS - L2 Switch Forwarding Database (CAM Table) Infrastructure Adapter
Executes non-blocking asynchronous SNMP walks (SNMPv3 with SHA/AES-128 and
SNMPv2c community fallback), delegates CAM table parsing to stateless snmp_cam_parser,
validates switchport bindings via SwitchportTelemetryPort, and publishes to
the Memurai event bus ('aetheris:telemetry:switch_fdb').
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UsmUserData,
    usmHMACSHAAuthProtocol,
    usmAesCfb128Protocol,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    walk_cmd,
)

from aetheris.core.ports.l2_switchport import SwitchportTelemetryPort
from aetheris.core.parsers.snmp_cam_parser import parse_cam_table_oids
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

logger = logging.getLogger("aetheris.adapters.snmp_fdb")


class SnmpFdbAdapter:
    """
    Decoupled L2 Switch Forwarding Database (CAM Table) Infrastructure Adapter.
    Executes tripartite MIB walking across dot1dTpFdbPort, dot1dBasePortIfIndex,
    and ifName OIDs with SNMPv3 / SNMPv2c fallback support.
    """

    DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
    DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
    IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"

    def __init__(
        self,
        community: str = "public",
        event_bus: Optional[MemuraiEventBus] = None,
        target_ip: Optional[str] = None,
        v3_user: str = "",
        v3_auth: str = "",
        v3_priv: str = "",
        timeout: float = 2.0,
        retries: int = 2,
        telemetry_context: Optional[Dict[str, Any]] = None,
    ):
        self.community = community
        self.bus = event_bus
        self.target_ip = target_ip
        self.queue_name = "aetheris:telemetry:switch_fdb"
        self.telemetry_context = telemetry_context or {}
        self.timeout = min(2.0, max(0.1, float(self.telemetry_context.get("timeout_sec", timeout))))
        self.retries = retries

        self.engine = SnmpEngine()
        self.snmp_engine = self.engine  # Alias for legacy compatibility
        self.context = ContextData()
        self.transports: Dict[str, Any] = {}

        # Configure SNMPv3 credentials (HMAC-SHA / AES-128) if provided
        if v3_user:
            self.auth_data = UsmUserData(
                userName=v3_user,
                authKey=v3_auth,
                privKey=v3_priv,
                authProtocol=usmHMACSHAAuthProtocol,
                privProtocol=usmAesCfb128Protocol,
            )
        else:
            self.auth_data = None

    def close(self) -> None:
        """Explicitly terminates the PySNMP transport dispatcher to prevent carrier leaks."""
        try:
            if hasattr(self.engine, "close_dispatcher"):
                self.engine.close_dispatcher()
            elif hasattr(self.engine, "transport_dispatcher") and self.engine.transport_dispatcher:
                self.engine.transport_dispatcher.close_dispatcher()
            elif hasattr(self.engine, "transportDispatcher") and self.engine.transportDispatcher:
                self.engine.transportDispatcher.closeDispatcher()
        except Exception as e:
            logger.debug(f"Error closing SNMP dispatcher: {e}")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    async def _get_transport(self, target_ip: str) -> Any:
        """Lazily creates and resolves the UDP transport target."""
        if target_ip not in self.transports:
            try:
                self.transports[target_ip] = await UdpTransportTarget.create(
                    (target_ip, 161),
                    timeout=self.timeout,
                    retries=self.retries,
                )
            except Exception:
                self.transports[target_ip] = UdpTransportTarget(
                    (target_ip, 161),
                    timeout=self.timeout,
                    retries=self.retries,
                )
        return self.transports[target_ip]

    async def _async_walk(self, target_ip: str, base_oid: str, auth_data: Any = None) -> Dict[str, Any]:
        """Executes a non-blocking asynchronous SNMP walk with specified or default credentials."""
        active_auth = auth_data or self.auth_data
        if not active_auth:
            return {}

        results: Dict[str, Any] = {}
        try:
            transport = await self._get_transport(target_ip)
            async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
                self.engine,
                active_auth,
                transport,
                self.context,
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                if errorIndication or errorStatus:
                    break
                for varBind in varBinds:
                    if varBind:
                        oid_obj, val_obj = varBind
                        results[str(oid_obj)] = val_obj
        except Exception as e:
            logger.debug(f"SNMP walk error on {target_ip} for OID {base_oid}: {e}")
        return results

    async def _extract_with_auth(self, target_ip: str, auth_data: Any) -> Dict[str, str]:
        """Runs the tripartite MIB extraction for a specific auth credential."""
        raw_cam_table = await self._async_walk(target_ip, self.DOT1D_TP_FDB_PORT, auth_data=auth_data)
        if not raw_cam_table:
            return {}

        raw_bridge_map = await self._async_walk(target_ip, self.DOT1D_BASE_PORT_IFINDEX, auth_data=auth_data)
        raw_ifname_map = await self._async_walk(target_ip, self.IF_NAME, auth_data=auth_data)

        return parse_cam_table_oids(raw_cam_table, raw_bridge_map, raw_ifname_map)

    async def extract_cam_matrix(self, target_ip: Optional[str] = None) -> Dict[str, str]:
        """
        Orchestrates tripartite MIB extraction with SNMPv3 first, then SNMPv2c fallback.
        Returns mapping: { "mac_address": "interface_name" }
        """
        ip = target_ip or self.target_ip
        if not ip:
            raise ValueError("Target IP address must be specified for CAM extraction.")

        cam_matrix: Dict[str, str] = {}
        # 1. SNMPv3 attempt if configured
        if self.auth_data:
            cam_matrix = await self._extract_with_auth(ip, self.auth_data)

        # 2. SNMPv2c fallback if CAM matrix is empty
        if not cam_matrix:
            communities = self.telemetry_context.get("snmp_communities") or [self.community]
            for comm in communities:
                v2c_auth = CommunityData(comm, mpModel=1)
                cam_matrix = await self._extract_with_auth(ip, v2c_auth)
                if cam_matrix:
                    break

        return cam_matrix

    # Compatibility alias for probers
    execute_cam_extraction = extract_cam_matrix

    async def crawl_switch(self, switch_ip: Optional[str] = None) -> List[SwitchportTelemetryPort]:
        """
        Crawls the switch CAM table, validates each entry as a SwitchportTelemetryPort,
        and publishes records to 'aetheris:telemetry:switch_fdb'.
        """
        ip = switch_ip or self.target_ip
        if not ip:
            raise ValueError("Target IP address must be specified for CAM crawl.")

        logger.info(f"Initiating FDB extraction on {ip}")
        cam_matrix = await self.extract_cam_matrix(ip)

        port_counts: Dict[str, int] = {}
        for ifname in cam_matrix.values():
            port_counts[ifname] = port_counts.get(ifname, 0) + 1

        telemetry_records: List[SwitchportTelemetryPort] = []
        for mac, ifname in cam_matrix.items():
            density = port_counts.get(ifname, 1)
            is_trunk = density >= 4 or "trunk" in ifname.lower() or "uplink" in ifname.lower()
            try:
                telemetry = SwitchportTelemetryPort(
                    switch_ip=ip,
                    mac_address=mac,
                    port_name=ifname,
                    vlan_id=1,
                    is_trunk=is_trunk,
                    mac_density=density,
                )
                telemetry_records.append(telemetry)
                if self.bus:
                    await self.bus.push_telemetry(self.queue_name, telemetry.model_dump())
            except Exception as e:
                logger.error(f"FDB telemetry validation failed for {mac} on {ip}: {e}")

        return telemetry_records
