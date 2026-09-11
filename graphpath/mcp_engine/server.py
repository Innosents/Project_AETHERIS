"""
GraphPath Model Context Protocol (MCP) Server
Provides a dual-mode server (FastMCP/MCPServer + Universal JSON-RPC 2.0 STDIO) for exposing
network discovery, topology graphs, and DIP datafiles to AI agents.
"""

import sys
import os
import json
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from mcp_engine.resources import GraphPathResourceManager
from mcp_engine.tools import GraphPathToolManager

class GraphPathMCPServer:
    """
    Standard MCP Server for GraphPath.
    Implements standard MCP protocol over STDIO.
    """
    def __init__(self, name: str = "graphpath-mcp-server", version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.resource_mgr = GraphPathResourceManager(BASE_DIR)
        self.tool_mgr = GraphPathToolManager(BASE_DIR)

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Processes an incoming JSON-RPC 2.0 MCP request."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "resources": {"subscribe": False, "listChanged": False},
                        "tools": {"listChanged": False},
                        "prompts": {"listChanged": False}
                    },
                    "serverInfo": {
                        "name": self.name,
                        "version": self.version
                    }
                }
            }

        elif method == "notifications/initialized":
            return {}

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        elif method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resources": self.resource_mgr.get_resource_list()
                }
            }

        elif method == "resources/read":
            uri = params.get("uri", "")
            data = self.resource_mgr.read_resource(uri)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(data, indent=2)
                        }
                    ]
                }
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.tool_mgr.get_tool_definitions()
                }
            }

        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            result = self.tool_mgr.execute_tool(tool_name, tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2)
                        }
                    ],
                    "isError": "error" in result
                }
            }

        elif method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "prompts": [
                        {
                            "name": "audit_network_security",
                            "description": "Analyze the active network topology, identify unclassified hosts, inspect open ports, and suggest security hardening actions.",
                            "arguments": []
                        },
                        {
                            "name": "reconcile_device_pathing",
                            "description": "Analyze intermediate infrastructure (Routers, Switches, Wi-Fi Extenders) and guide the user in setting accurate physical cabling uplinks.",
                            "arguments": []
                        }
                    ]
                }
            }

        elif method == "prompts/get":
            prompt_name = params.get("name")
            if prompt_name == "audit_network_security":
                snapshot = self.tool_mgr.get_topology_snapshot()
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "description": "Security audit prompt for active network topology",
                        "messages": [
                            {
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": f"Please audit the following network topology discovery snapshot and identify any rogue devices, risky open ports (e.g. Telnet, unencrypted HTTP, cleartext SCADA), or misclassified hosts:\n\n```json\n{json.dumps(snapshot, indent=2)}\n```"
                                }
                            }
                        ]
                    }
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Prompt '{prompt_name}' not found"}
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"}
        }

    def run_stdio(self):
        """Runs the MCP server over standard input/output (STDIO)."""
        sys.stderr.write(f"[{self.name}] GraphPath MCP Datafile Server initialized (STDIO)\n")
        sys.stderr.flush()

        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                request = json.loads(line)
                response = self.handle_request(request)

                if response:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()

            except (KeyboardInterrupt, EOFError):
                break
            except Exception as e:
                sys.stderr.write(f"[{self.name} Error] Exception handling STDIO frame: {e}\n")
                sys.stderr.flush()

def create_fastmcp_server():
    """
    Constructs a FastMCP/MCPServer instance if the mcp Python library is installed.
    """
    try:
        try:
            from mcp.server.mcpserver import MCPServer as FastMCP
        except ImportError:
            from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("GraphPath Network Intelligence")
        tool_mgr = GraphPathToolManager(BASE_DIR)
        res_mgr = GraphPathResourceManager(BASE_DIR)

        @mcp.resource("graphpath://topology/current")
        def current_topology() -> str:
            return json.dumps(res_mgr.read_resource("graphpath://topology/current"), indent=2)

        @mcp.resource("graphpath://profiles/dip")
        def dip_profiles() -> str:
            return json.dumps(res_mgr.read_resource("graphpath://profiles/dip"), indent=2)

        @mcp.resource("graphpath://history/latest")
        def latest_history() -> str:
            return json.dumps(res_mgr.read_resource("graphpath://history/latest"), indent=2)

        @mcp.tool()
        def get_topology_snapshot() -> dict:
            """Returns the complete active network topology graph."""
            return tool_mgr.get_topology_snapshot()

        @mcp.tool()
        def inspect_device(identifier: str) -> dict:
            """Retrieves deep telemetry for a specific network device (IP or MAC)."""
            return tool_mgr.inspect_device(identifier)

        @mcp.tool()
        def search_devices(query: str = "", device_type: str = "", open_port: Optional[int] = None) -> dict:
            """Searches and filters network devices."""
            return tool_mgr.search_devices(query, device_type, open_port)

        @mcp.tool()
        def pin_device_identity(profile_id: str, custom_type: str, custom_vendor: str = "Generic", custom_model: str = "Device", uplink_ip: str = "") -> dict:
            """Locks a custom user identity and physical uplink in DIP."""
            return tool_mgr.pin_device_identity(profile_id, custom_type, custom_vendor, custom_model, uplink_ip)

        @mcp.tool()
        def list_discovery_history() -> dict:
            """Lists all historical snapshot files on disk."""
            return tool_mgr.list_discovery_history()

        @mcp.tool()
        def export_topology_data(format: str = "json") -> dict:
            """Exports topology to JSON, CSV, or DOT format."""
            return tool_mgr.export_topology_data(format)

        return mcp
    except (ImportError, ModuleNotFoundError):
        return None

if __name__ == "__main__":
    server = GraphPathMCPServer()
    server.run_stdio()

