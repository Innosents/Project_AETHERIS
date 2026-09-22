"""
Project AETHERIS - Chassis Intelligence Adapter & Compatibility Bridge.
Connects orchestrator delegates with ErspanChassisAdapter and maintains chassis_matrix state.
"""

from typing import Optional, Dict, Any
from aetheris.infrastructure.adapters.erspan_chassis_adapter import ErspanChassisAdapter


class ChassisIntelligenceProbe:
    """
    Adapter bridge providing compatibility for ChassisIntelligenceProbe interfaces
    while delegating wire parsing to ErspanChassisAdapter.
    """

    def __init__(
        self,
        interface: str = "",
        telemetry_context: Optional[Dict[str, Any]] = None,
        event_bus: Any = None,
    ) -> None:
        self.interface = interface
        self.telemetry_context = telemetry_context or {}
        self.bus = event_bus
        self.chassis_matrix: Dict[str, Any] = {}
        if self.bus is not None:
            span_iface = self.telemetry_context.get("span_interface", interface or "eth0")
            self.adapter: Optional[ErspanChassisAdapter] = ErspanChassisAdapter(
                interface=span_iface,
                ingestion_ip="",
                event_bus=self.bus,
            )
        else:
            self.adapter = None

    def _frame_callback(self, packet: Any) -> None:
        """Callback invoked by SpanCaptureEngine delegate multiplexer."""
        if self.adapter is not None:
            self.adapter._frame_callback(packet)

    async def execute(self) -> Dict[str, Any]:
        """Returns the current chassis matrix state."""
        return self.chassis_matrix

    async def rollback(self) -> bool:
        """Resets the internal chassis matrix."""
        self.chassis_matrix.clear()
        return True

