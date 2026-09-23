"""AETHERIS HWOT (Hardware OT) MCP Microserver (mcp 2.x native).

Spawns ephemeral mock loopback responders for industrial protocols
(EtherNet/IP CIP, Siemens S7Comm ISO-on-TCP) to allow local, offline integration testing.
"""

from typing import Any, Dict
from aetheris.mcp.hwot import (
    HwotSimulatorEngine,
    default_hwot_engine,
    HwotSimulatorPort,
    HwotServerStatus,
    HwotTerminationResult,
    hwot_spawn_cip_plc,
    hwot_spawn_s7_plc,
    hwot_kill_all,
    ACTIVE_SERVERS,
)

try:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("aetheris-hwot")
except Exception:
    mcp = None


if mcp:
    @mcp.tool()
    def mcp_hwot_spawn_cip_plc(port: int = 44818) -> Dict[str, Any]:
        """Launch an ephemeral EtherNet/IP CIP PLC mock on 127.0.0.1."""
        res = hwot_spawn_cip_plc(port=port)
        return dict(res)

    @mcp.tool()
    def mcp_hwot_spawn_s7_plc(port: int = 10102) -> Dict[str, Any]:
        """Launch an ephemeral Siemens S7Comm ISO-on-TCP mock on 127.0.0.1."""
        res = hwot_spawn_s7_plc(port=port)
        return dict(res)

    @mcp.tool()
    def mcp_hwot_kill_all() -> Dict[str, Any]:
        """Terminate all active loopback hardware simulators."""
        res = hwot_kill_all()
        return dict(res)


if __name__ == "__main__" and mcp:
    mcp.run(transport="stdio")
