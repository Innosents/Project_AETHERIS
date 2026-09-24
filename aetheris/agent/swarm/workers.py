from aetheris.agent.swarm.base_node import SwarmNode
from aetheris.core.ports.telemetry_ledger import TelemetryLedgerPort

class DiscoveryNode(SwarmNode):
    def __init__(self, ledger: TelemetryLedgerPort):
        super().__init__(
            name="Discovery",
            instructions="You are the physical layer prober. Execute network sweeps and parse MAC/IP tables. Write raw telemetry to the ledger.",
            allowed_tools=["arp_scan", "snmp_fdb_crawler", "raw_packet_tap", "modbus_discover"],
            ledger=ledger
        )

class CartographerNode(SwarmNode):
    def __init__(self, ledger: TelemetryLedgerPort):
        super().__init__(
            name="Cartographer",
            instructions="You are the spatial mathematician. Read raw telemetry from the ledger, resolve the Bayesian topology, and update the graph.",
            allowed_tools=["spatial_bayesian", "kalman_filter", "topologies_projection"],
            ledger=ledger
        )