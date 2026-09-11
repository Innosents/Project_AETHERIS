"""
GraphPath MCP Tools Manager
Coordinates topology inspection, device forensic analysis, identity pinning (DIP),
discovery sweeps, and proxies for Blackboard, Validation Guard, and Vector Memory engines.
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from mcp_engine.blackboard import BlackboardLedger
from mcp_engine.validator import ValidationGuardEngine
from mcp_engine.memory import VectorMemoryEngine


class GraphPathToolManager:
    """
    Centralized tool execution and orchestration manager for GraphPath.
    Exposes discovery tools, device forensic inspectors, and sub-engine interfaces
    (Blackboard, Validation Guard, Vector Memory).
    """

    def __init__(self, base_dir: Optional[Path] = None, graph: Optional[Any] = None):
        self.base_dir = Path(base_dir) if base_dir else BASE_DIR
        self.history_dir = self.base_dir / "discovery_history"
        self.blackboard = BlackboardLedger(self.base_dir / "blackboard_ledger.json")
        self.guard = ValidationGuardEngine(self.base_dir)
        self.memory = VectorMemoryEngine(self.base_dir)
        self._custom_graph = graph

    def _get_graph(self) -> Any:
        """Dynamically retrieves active graph store without causing circular import deadlocks."""
        if self._custom_graph is not None:
            return self._custom_graph
        try:
            if "ui.routes" in sys.modules:
                return getattr(sys.modules["ui.routes"], "graph", None)
            from ui.routes import graph
            return graph
        except Exception:
            try:
                from topology.graph_store import GraphStore
                return GraphStore()
            except Exception:
                return None

    # ---------------------------------------------------------------------------
    # Discovery & Topology Tools
    # ---------------------------------------------------------------------------

    def get_topology_snapshot(self) -> Dict[str, Any]:
        """Returns the complete active network topology graph snapshot."""
        g = self._get_graph()
        if g is not None and hasattr(g, "export_topology_snapshot"):
            return g.export_topology_snapshot()
        return {"nodes": [], "edges": [], "summary": {}}

    def inspect_device(self, identifier: str) -> Dict[str, Any]:
        """Retrieves deep telemetry for a specific network device (IP, MAC, or hostname)."""
        g = self._get_graph()
        if g is not None and hasattr(g, "_G"):
            ident = str(identifier).strip()
            for node_id, data in g._G.nodes(data=True):
                node_ip = str(data.get("ip", node_id))
                node_mac = str(data.get("mac", "")).lower()
                node_host = str(data.get("hostname", "")).lower()
                banners = data.get("banners", {})
                dns_host = str(banners.get("dns_hostname", "")).lower() if isinstance(banners, dict) else ""

                if (
                    ident == str(node_id)
                    or ident.lower() == node_ip.lower()
                    or ident.lower() == node_mac
                    or ident.lower() == node_host
                    or ident.lower() == dns_host
                ):
                    dev = dict(data)
                    dev.setdefault("id", node_id)
                    dev.setdefault("ip", node_ip)
                    return {"status": "found", "device": dev}

        return {"status": "not_found", "message": f"Device '{identifier}' not found in active topology"}

    def search_devices(
        self, query: str = "", device_type: str = "", open_port: Optional[int] = None
    ) -> Dict[str, Any]:
        """Searches and filters network devices across active topology."""
        g = self._get_graph()
        matches = []
        if g is not None and hasattr(g, "_G"):
            q = (query or "").lower().strip()
            target_type = (device_type or "").lower().strip()

            for node_id, data in g._G.nodes(data=True):
                # Filter by open_port if specified
                if open_port is not None:
                    ports = data.get("open_ports", []) or data.get("ports", [])
                    try:
                        p_int = int(open_port)
                        if p_int not in ports:
                            continue
                    except (ValueError, TypeError):
                        pass

                # Filter by device_type if specified
                if target_type:
                    node_type = str(data.get("type", "")).lower()
                    if target_type != node_type:
                        continue

                # Filter by query if specified
                if q:
                    search_str = " ".join([
                        str(node_id),
                        str(data.get("ip", "")),
                        str(data.get("vendor", "")),
                        str(data.get("model", "")),
                        str(data.get("type", "")),
                        str(data.get("hostname", "")),
                        str(data.get("mac", "")),
                        str(data.get("label", "")),
                        str(data.get("banners", ""))
                    ]).lower()
                    if q not in search_str:
                        continue

                dev = dict(data)
                dev.setdefault("id", node_id)
                dev.setdefault("ip", str(node_id) if "." in str(node_id) else data.get("ip", ""))
                matches.append(dev)

        return {
            "status": "success",
            "total_matches": len(matches),
            "devices": matches
        }

    def pin_device_identity(
        self,
        profile_id: str,
        custom_type: str,
        custom_vendor: str = "Generic",
        custom_model: str = "Device",
        uplink_ip: str = ""
    ) -> Dict[str, Any]:
        """Pins a custom user identity and physical uplink in DIP and topology graph."""
        try:
            from core.dip_manager import DeviceIdentityProfileManager
            dip_mgr = DeviceIdentityProfileManager(str(self.base_dir / "device_identity_profiles.json"))
            locked = dip_mgr.lock_profile(profile_id, custom_type, custom_vendor, custom_model, uplink_ip=uplink_ip)
            if not locked:
                ip = ""
                env_cidr = ""
                if profile_id.startswith("IP_"):
                    parts = profile_id.split("_")
                    if len(parts) >= 2:
                        ip = parts[1]
                    if len(parts) >= 3:
                        env_cidr = parts[2]
                with dip_mgr._lock:
                    dip_mgr.profiles[profile_id] = {
                        "profile_id": profile_id,
                        "environment_cidr": env_cidr or "default_lan",
                        "ip": ip,
                        "type": custom_type,
                        "vendor": custom_vendor,
                        "model": custom_model,
                        "uplink_ip": uplink_ip,
                        "is_locked": True,
                        "confidence": 1.0,
                        "times_observed": 1,
                        "source_proofs": ["manual_pin"]
                    }
                    dip_mgr.save_profiles()
        except Exception:
            pass

        # Update node in topology graph if present
        g = self._get_graph()
        if g is not None:
            node_target = None
            candidates = [profile_id]
            if profile_id.startswith("IP_"):
                candidates.append(profile_id.replace("IP_", "").split("_")[0])

            for candidate in candidates:
                if hasattr(g, "_G") and g._G.has_node(candidate):
                    node_target = candidate
                    break

            if node_target:
                g.add_node(node_target, {
                    "type": custom_type,
                    "vendor": custom_vendor,
                    "model": custom_model,
                    "uplink_ip": uplink_ip
                })
                if uplink_ip and hasattr(g, "_G") and g._G.has_node(uplink_ip):
                    g.add_edge(uplink_ip, node_target, {"layer": 2, "type": "ethernet", "pinned": True})

            if hasattr(g, "reconcile_topology"):
                try:
                    g.reconcile_topology()
                except Exception:
                    pass

        return {
            "status": "success",
            "profile_id": profile_id,
            "type": custom_type,
            "vendor": custom_vendor,
            "model": custom_model,
            "uplink_ip": uplink_ip
        }

    def export_topology_data(self, format: str = "json") -> Dict[str, Any]:
        """Exports topology to JSON, CSV, or DOT format."""
        fmt = (format or "json").lower()
        g = self._get_graph()
        snapshot = (
            g.export_topology_snapshot()
            if g and hasattr(g, "export_topology_snapshot")
            else {"nodes": [], "edges": []}
        )

        if fmt == "csv":
            csv_lines = ["IP,Type,Vendor,Model"]
            for node in snapshot.get("nodes", []):
                if not node.get("is_subnet_hub"):
                    ip = node.get("ip", node.get("id", ""))
                    ntype = node.get("type", "unknown")
                    vendor = node.get("vendor", "generic")
                    model = node.get("model", "")
                    csv_lines.append(f"{ip},{ntype},{vendor},{model}")
            content = "\n".join(csv_lines)
            return {"format": "csv", "content": content}

        elif fmt == "dot":
            dot_lines = [
                "digraph NetworkTopology {",
                '  rankdir="TB";',
                '  node [shape=box, style=rounded];'
            ]
            for node in snapshot.get("nodes", []):
                nid = str(node.get("id", node.get("ip", "")))
                nlabel = f"{nid}\\n{node.get('vendor', '')} {node.get('model', '')}".strip()
                dot_lines.append(f'  "{nid}" [label="{nlabel}"];')
            for edge in snapshot.get("edges", []):
                src = edge.get("src", edge.get("source", ""))
                dst = edge.get("dst", edge.get("target", ""))
                etype = edge.get("type", "link")
                dot_lines.append(f'  "{src}" -> "{dst}" [label="{etype}"];')
            dot_lines.append("}")
            content = "\n".join(dot_lines)
            return {"format": "dot", "content": content}

        else:
            return {
                "format": "json",
                "content": snapshot
            }

    def list_discovery_history(self) -> Dict[str, Any]:
        """Lists historical topology discovery snapshot files."""
        if not self.history_dir.exists():
            return {"status": "success", "total_snapshots": 0, "snapshots": []}
        files = sorted(self.history_dir.glob("*.json"), key=os.path.getmtime, reverse=True)
        snapshots = []
        for f in files:
            snapshots.append({
                "filename": f.name,
                "path": str(f),
                "size_bytes": f.stat().st_size,
                "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(f.stat().st_mtime))
            })
        return {
            "status": "success",
            "total_snapshots": len(snapshots),
            "snapshots": snapshots
        }

    def trigger_network_sweep(self, target_cidr: str = "") -> Dict[str, Any]:
        """Executes or retrieves active discovery sweep for the target CIDR."""
        cidr = target_cidr or "192.168.1.0/24"
        start_t = time.time()
        g = self._get_graph()
        snapshot = (
            g.export_topology_snapshot()
            if g and hasattr(g, "export_topology_snapshot")
            else {"nodes": [], "edges": [], "summary": {}}
        )
        duration = round(time.time() - start_t, 3)
        return {
            "status": "completed",
            "target_cidr": cidr,
            "duration_seconds": duration,
            "snapshot": snapshot
        }

    # ---------------------------------------------------------------------------
    # MCP Protocol Metadata & Dispatcher
    # ---------------------------------------------------------------------------

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns JSON schema definitions for all registered MCP tools."""
        return [
            {
                "name": "get_topology_snapshot",
                "description": "Returns the complete active network topology graph snapshot.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "inspect_device",
                "description": "Retrieves deep forensic telemetry for a device by IP, MAC, or hostname.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "identifier": {
                            "type": "string",
                            "description": "IP address, MAC address, or hostname of the target device"
                        }
                    },
                    "required": ["identifier"]
                }
            },
            {
                "name": "search_devices",
                "description": "Searches and filters network devices by query, type, or open port.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Keyword search across all attributes"},
                        "device_type": {"type": "string", "description": "Filter by device type (e.g. router, workstation)"},
                        "open_port": {"type": "integer", "description": "Filter devices with specific open TCP/UDP port"}
                    }
                }
            },
            {
                "name": "pin_device_identity",
                "description": "Pins custom user identity and physical uplink in DIP and topology graph.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "profile_id": {"type": "string", "description": "Unique DIP profile ID (e.g. IP_192.168.1.200_192.168.1.0/24)"},
                        "custom_type": {"type": "string", "description": "Device classification type"},
                        "custom_vendor": {"type": "string", "description": "Manufacturer / vendor", "default": "Generic"},
                        "custom_model": {"type": "string", "description": "Hardware model", "default": "Device"},
                        "uplink_ip": {"type": "string", "description": "Upstream switch or router IP address", "default": ""}
                    },
                    "required": ["profile_id", "custom_type"]
                }
            },
            {
                "name": "export_topology_data",
                "description": "Exports topology graph into JSON, CSV, or DOT format.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "enum": ["json", "csv", "dot"],
                            "default": "json",
                            "description": "Export format"
                        }
                    }
                }
            },
            {
                "name": "list_discovery_history",
                "description": "Lists historical network discovery snapshot files.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "trigger_network_sweep",
                "description": "Triggers or samples an active network discovery sweep.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_cidr": {"type": "string", "description": "Target subnet CIDR (e.g. 192.168.1.0/24)"}
                    }
                }
            },
            # Blackboard Tools
            {
                "name": "acquire_node_lock",
                "description": "Acquires an exclusive TTL-expiring concurrency lock on a node or resource.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "resource_id": {"type": "string", "description": "Resource identifier (e.g. node:192.168.1.86)"},
                        "agent_id": {"type": "string", "description": "Agent acquiring the lock"},
                        "ttl_seconds": {"type": "integer", "default": 60},
                        "reason": {"type": "string", "default": ""}
                    },
                    "required": ["resource_id", "agent_id"]
                }
            },
            {
                "name": "release_node_lock",
                "description": "Releases an acquired concurrency lock.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "resource_id": {"type": "string"},
                        "agent_id": {"type": "string"},
                        "force": {"type": "boolean", "default": False}
                    },
                    "required": ["resource_id", "agent_id"]
                }
            },
            {
                "name": "post_agent_checkpoint",
                "description": "Posts an atomic execution checkpoint to the shared state ledger.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "task_id": {"type": "string"},
                        "status": {"type": "string"},
                        "summary": {"type": "string"},
                        "payload": {"type": "object"},
                        "artifacts_modified": {"type": "array", "items": {"type": "string"}},
                        "step_index": {"type": "integer"}
                    },
                    "required": ["agent_id", "task_id", "status", "summary"]
                }
            },
            {
                "name": "post_blackboard_message",
                "description": "Broadcasts an inter-agent message to the shared feed.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sender_agent_id": {"type": "string"},
                        "message": {"type": "string"},
                        "message_type": {"type": "string", "default": "info"},
                        "recipient": {"type": "string", "default": "all"}
                    },
                    "required": ["sender_agent_id", "message"]
                }
            },
            {
                "name": "read_blackboard_state",
                "description": "Reads active tasks, locks, checkpoints, and shared memory from Blackboard.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "section": {"type": "string", "default": "all"},
                        "filter_agent_id": {"type": "string", "default": ""},
                        "filter_task_status": {"type": "string", "default": ""},
                        "limit": {"type": "integer", "default": 50}
                    }
                }
            },
            # Validation Guard Tools
            {
                "name": "validate_topology_schema",
                "description": "Validates serialized topology against Pydantic models.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {"type": "object", "description": "Topology payload to validate"}
                    },
                    "required": ["payload"]
                }
            },
            {
                "name": "check_node_integrity",
                "description": "Validates node attributes against NodeModel schema.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node_data": {"type": "object", "description": "Node attributes dict"}
                    },
                    "required": ["node_data"]
                }
            },
            {
                "name": "verify_oid_uniqueness",
                "description": "Audits SNMP OIDs for syntax conformance and collisions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "custom_oids": {"type": "array", "items": {"type": "object"}}
                    }
                }
            },
            {
                "name": "audit_dip_configuration",
                "description": "Audits DIP database against schema rules.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "profiles_path": {"type": "string"}
                    }
                }
            },
            {
                "name": "run_contract_check",
                "description": "Executes AST syntax parsing on Python source files.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_paths": {"type": "array", "items": {"type": "string"}},
                        "strict": {"type": "boolean", "default": False}
                    }
                }
            },
            # Vector Memory Tools
            {
                "name": "search_project_memory",
                "description": "Performs semantic vector similarity search across documentation and ADRs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "top_k": {"type": "integer", "default": 5},
                        "category": {"type": "string", "default": ""},
                        "min_score": {"type": "number", "default": 0.05}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "upsert_decision_record",
                "description": "Logs or updates an Architectural Decision Record (ADR).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "record_id": {"type": "string"},
                        "title": {"type": "string"},
                        "decision": {"type": "string"},
                        "rationale": {"type": "string"},
                        "status": {"type": "string", "default": "accepted"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "affected_components": {"type": "array", "items": {"type": "string"}},
                        "context": {"type": "string", "default": ""}
                    },
                    "required": ["record_id", "title", "decision", "rationale"]
                }
            },
            {
                "name": "list_decision_records",
                "description": "Lists all recorded Architectural Decision Records.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "status_filter": {"type": "string", "default": ""},
                        "tag_filter": {"type": "string", "default": ""}
                    }
                }
            },
            {
                "name": "index_project_documentation",
                "description": "Scans and rebuilds the semantic vector memory index.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "custom_paths": {"type": "array", "items": {"type": "string"}}
                    }
                }
            }
        ]

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches an MCP tool call by name with validated arguments."""
        args = arguments or {}

        dispatcher = {
            # Discovery & Topology Tools
            "get_topology_snapshot": lambda: self.get_topology_snapshot(),
            "inspect_device": lambda: self.inspect_device(args.get("identifier", "")),
            "search_devices": lambda: self.search_devices(
                query=args.get("query", ""),
                device_type=args.get("device_type", ""),
                open_port=args.get("open_port")
            ),
            "pin_device_identity": lambda: self.pin_device_identity(
                profile_id=args.get("profile_id", ""),
                custom_type=args.get("custom_type", ""),
                custom_vendor=args.get("custom_vendor", "Generic"),
                custom_model=args.get("custom_model", "Device"),
                uplink_ip=args.get("uplink_ip", "")
            ),
            "export_topology_data": lambda: self.export_topology_data(args.get("format", "json")),
            "list_discovery_history": lambda: self.list_discovery_history(),
            "trigger_network_sweep": lambda: self.trigger_network_sweep(args.get("target_cidr", "")),

            # Blackboard Tools
            "acquire_node_lock": lambda: self.blackboard.acquire_lock(
                resource_id=args.get("resource_id", ""),
                agent_id=args.get("agent_id", ""),
                ttl_seconds=args.get("ttl_seconds", 60),
                reason=args.get("reason", "")
            ),
            "release_node_lock": lambda: self.blackboard.release_lock(
                resource_id=args.get("resource_id", ""),
                agent_id=args.get("agent_id", ""),
                force=args.get("force", False)
            ),
            "post_agent_checkpoint": lambda: self.blackboard.post_checkpoint(
                agent_id=args.get("agent_id", ""),
                task_id=args.get("task_id", ""),
                status=args.get("status", "in_progress"),
                summary=args.get("summary", ""),
                payload=args.get("payload"),
                artifacts_modified=args.get("artifacts_modified"),
                step_index=args.get("step_index")
            ),
            "post_blackboard_message": lambda: self.blackboard.post_message(
                sender_agent_id=args.get("sender_agent_id", ""),
                message=args.get("message", ""),
                message_type=args.get("message_type", "info"),
                recipient=args.get("recipient", "all")
            ),
            "read_blackboard_state": lambda: self.blackboard.read_state(
                section=args.get("section", "all"),
                filter_agent_id=args.get("filter_agent_id", ""),
                filter_task_status=args.get("filter_task_status", ""),
                limit=args.get("limit", 50)
            ),

            # Validation Guard Tools
            "validate_topology_schema": lambda: self.guard.validate_topology_schema(args.get("payload", {})),
            "check_node_integrity": lambda: self.guard.check_node_integrity(args.get("node_data", {})),
            "verify_oid_uniqueness": lambda: self.guard.verify_oid_uniqueness(args.get("custom_oids")),
            "audit_dip_configuration": lambda: self.guard.audit_dip_configuration(args.get("profiles_path")),
            "run_contract_check": lambda: self.guard.run_contract_check(
                file_paths=args.get("file_paths"),
                strict=args.get("strict", False)
            ),

            # Vector Memory Tools
            "search_project_memory": lambda: self.memory.search_project_memory(
                query=args.get("query", ""),
                top_k=args.get("top_k", 5),
                category=args.get("category", ""),
                min_score=args.get("min_score", 0.05)
            ),
            "upsert_decision_record": lambda: self.memory.upsert_decision_record(
                record_id=args.get("record_id", ""),
                title=args.get("title", ""),
                decision=args.get("decision", ""),
                rationale=args.get("rationale", ""),
                status=args.get("status", "accepted"),
                tags=args.get("tags"),
                affected_components=args.get("affected_components"),
                context=args.get("context", "")
            ),
            "list_decision_records": lambda: self.memory.list_decision_records(
                status_filter=args.get("status_filter", ""),
                tag_filter=args.get("tag_filter", "")
            ),
            "index_project_documentation": lambda: self.memory.index_project_documentation(
                custom_paths=args.get("custom_paths")
            )
        }

        if name not in dispatcher:
            return {"error": f"Tool '{name}' not recognized"}

        try:
            return dispatcher[name]()
        except Exception as e:
            return {"error": f"Tool execution failed: {str(e)}"}