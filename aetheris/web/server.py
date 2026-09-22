"""
Project AETHERIS - Web Visualizer Bridge Server
Exposes the Cytoscape spatial topology visualizer bridge application.
Re-exports the unified spatial server instance from aetheris.mcp.spatial_server.
"""

from aetheris.mcp.spatial_server import (
    app,
    latest_telemetry,
    active_store,
    run_visualizer_server,
    HTML_DASHBOARD,
    TelemetryIngestPayload,
)

__all__ = [
    "app",
    "latest_telemetry",
    "active_store",
    "run_visualizer_server",
    "HTML_DASHBOARD",
    "TelemetryIngestPayload",
]

if __name__ == "__main__":
    run_visualizer_server()

