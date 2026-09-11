"""
GraphPath MCP Resources Provider
Exposes GraphPath datafiles (topology snapshots, DIP records, environment profiles, history),
Agent Blackboard ledger, Validation Guard schemas, and Vector Memory ADR stores as standard MCP Resource URIs.
"""

import os
import json
import glob
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp_engine.blackboard import BlackboardLedger
from mcp_engine.validator import ValidationGuardEngine
from mcp_engine.memory import VectorMemoryEngine
from mcp_engine.validation_models import (
    NodeModel,
    EdgeModel,
    SummaryModel,
    TopologyPayloadModel,
    DIPProfileModel,
    OIDModel
)

BASE_DIR = Path(__file__).resolve().parent.parent

class GraphPathResourceManager:
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or BASE_DIR
        self.history_dir = self.base_dir / "discovery_history"
        self.dip_path = self.base_dir / "device_identity_profiles.json"
        self.env_path = self.base_dir / "environment_profiles.json"
        self.blackboard = BlackboardLedger(self.base_dir / "blackboard_ledger.json")
        self.guard = ValidationGuardEngine(self.base_dir)
        self.memory = VectorMemoryEngine(self.base_dir)

    def get_resource_list(self) -> List[Dict[str, Any]]:
        """Returns the list of available MCP resource definitions."""
        resources = [
            # Master Orchestrator Resources
            {
                "uri": "orchestrator://status/cluster",
                "name": "Master Orchestrator Cluster Status",
                "description": "Unified operational state of the multi-agent cluster and registered engines",
                "mimeType": "application/json"
            },
            {
                "uri": "orchestrator://health/unified",
                "name": "Unified System Health Audit",
                "description": "Comprehensive full-system audit across OIDs, DIP profiles, syntax gates, and memory",
                "mimeType": "application/json"
            },

            # Vector Memory & ADR Resources
            {
                "uri": "memory://decisions/all",
                "name": "Architectural Decision Records (ADRs)",
                "description": "All recorded architectural decisions, refactoring rationales, and design trade-offs",
                "mimeType": "application/json"
            },
            {
                "uri": "memory://index/stats",
                "name": "Vector Memory Index Statistics",
                "description": "Vector memory health, total indexed chunks, and category distribution",
                "mimeType": "application/json"
            },

            # Validation Guard Resources
            {
                "uri": "guard://rules/schema",
                "name": "Validation Guard JSON Schemas",
                "description": "Formal Pydantic JSON schemas for Node, Edge, Topology, DIP, and OID models",
                "mimeType": "application/json"
            },
            {
                "uri": "guard://status/audit",
                "name": "Live Validation Guard Audit",
                "description": "Comprehensive compliance audit across OID uniqueness, DIP configuration, and syntax contracts",
                "mimeType": "application/json"
            },

            # Blackboard Resources
            {
                "uri": "blackboard://state/current",
                "name": "Active Blackboard State Ledger",
                "description": "Real-time state of all active agent tasks, locks, checkpoints, and shared memory",
                "mimeType": "application/json"
            },
            {
                "uri": "blackboard://locks/active",
                "name": "Active Concurrency Resource Locks",
                "description": "Active node and resource locks with remaining TTL expirations",
                "mimeType": "application/json"
            },
            {
                "uri": "blackboard://checkpoints/recent",
                "name": "Recent Agent Checkpoints",
                "description": "Stream of recent atomic execution checkpoints and milestones",
                "mimeType": "application/json"
            },

            # Discovery & Datafile Resources
            {
                "uri": "graphpath://topology/current",
                "name": "Live Network Topology",
                "description": "Current real-time network topology graph (nodes, edges, active subnets, asset summaries)",
                "mimeType": "application/json"
            },
            {
                "uri": "graphpath://profiles/dip",
                "name": "Device Identity Profiles (DIP)",
                "description": "Learned and user-pinned hardware fingerprints, MAC OUIs, hostnames, and custom uplink pathing",
                "mimeType": "application/json"
            },
            {
                "uri": "graphpath://profiles/environments",
                "name": "Environment Configurations",
                "description": "Configured environment CIDRs, core switch gateways, and active subnet scan targets",
                "mimeType": "application/json"
            },
            {
                "uri": "graphpath://history/latest",
                "name": "Latest Discovery Snapshot",
                "description": "The most recently archived discovery snapshot datafile on disk",
                "mimeType": "application/json"
            }
        ]

        # Dynamically append available historical snapshots
        if self.history_dir.exists():
            for p in sorted(self.history_dir.glob("snapshot_*.json"), reverse=True)[:10]:
                resources.append({
                    "uri": f"graphpath://history/{p.name}",
                    "name": f"Historical Snapshot: {p.name}",
                    "description": f"Archived discovery snapshot datafile from {p.name}",
                    "mimeType": "application/json"
                })

        return resources

    def read_resource(self, uri: str) -> Dict[str, Any]:
        """Reads and parses the JSON datafile corresponding to the given MCP resource URI."""
        clean_uri = uri.strip()

        # Master Orchestrator URIs
        if clean_uri == "orchestrator://status/cluster":
            return {
                "cluster_name": "GraphPath-Master-Orchestrator",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "registered_subsystems": ["Validation Guard", "Agent Blackboard", "Vector Search Memory", "Discovery Engine"],
                "blackboard": self.blackboard.read_state(section="all"),
                "memory_stats": self.memory.get_memory_stats()
            }
        elif clean_uri == "orchestrator://health/unified":
            from orchestrator_server import orchestrate_unified_audit
            return orchestrate_unified_audit()

        # Vector Memory & ADR URIs
        if clean_uri == "memory://decisions/all":
            return self.memory.list_decision_records()

        elif clean_uri == "memory://index/stats":
            return self.memory.get_memory_stats()

        # Validation Guard URIs
        elif clean_uri == "guard://rules/schema":
            return {
                "NodeModel": NodeModel.model_json_schema(),
                "EdgeModel": EdgeModel.model_json_schema(),
                "TopologyPayloadModel": TopologyPayloadModel.model_json_schema(),
                "DIPProfileModel": DIPProfileModel.model_json_schema(),
                "OIDModel": OIDModel.model_json_schema()
            }

        elif clean_uri == "guard://status/audit":
            oid_audit = self.guard.verify_oid_uniqueness()
            dip_audit = self.guard.audit_dip_configuration()
            contract_check = self.guard.run_contract_check()
            overall_pass = oid_audit.get("valid", False) and dip_audit.get("valid", False) and contract_check.get("gate_passed", False)
            return {
                "overall_status": "passed" if overall_pass else "failed",
                "oid_audit": oid_audit,
                "dip_audit": dip_audit,
                "contract_check": contract_check
            }

        # Blackboard URIs
        elif clean_uri == "blackboard://state/current":
            return self.blackboard.read_state(section="all")

        elif clean_uri == "blackboard://locks/active":
            return self.blackboard.read_state(section="locks")

        elif clean_uri == "blackboard://checkpoints/recent":
            return self.blackboard.read_state(section="checkpoints", limit=20)

        # GraphPath Datafile URIs
        elif clean_uri == "graphpath://topology/current":
            return self._get_current_topology()

        elif clean_uri == "graphpath://profiles/dip":
            return self._read_json_file(self.dip_path, fallback={})

        elif clean_uri == "graphpath://profiles/environments":
            return self._read_json_file(self.env_path, fallback={})

        elif clean_uri == "graphpath://history/latest":
            latest_file = self._get_latest_history_file()
            if latest_file and latest_file.exists():
                return self._read_json_file(latest_file, fallback={})
            return {"error": "No discovery history snapshots found on disk", "nodes": [], "edges": []}

        elif clean_uri.startswith("graphpath://history/"):
            filename = clean_uri.replace("graphpath://history/", "")
            target_path = self.history_dir / filename
            if target_path.exists():
                return self._read_json_file(target_path, fallback={})
            return {"error": f"Snapshot datafile '{filename}' not found"}

        return {"error": f"Unknown resource URI: {clean_uri}"}

    def _get_current_topology(self) -> Dict[str, Any]:
        """Retrieves the live topology from memory or the latest disk snapshot."""
        try:
            from ui.routes import graph
            snapshot = graph.export_topology_snapshot()
            if snapshot and snapshot.get("nodes"):
                return snapshot
        except Exception:
            pass

        # Fallback to latest historical snapshot if engine is idle
        latest_file = self._get_latest_history_file()
        if latest_file and latest_file.exists():
            return self._read_json_file(latest_file, fallback={"nodes": [], "edges": []})

        return {
            "nodes": [],
            "edges": [],
            "summary": {
                "total_assets": 0,
                "routers": 0,
                "switches": 0,
                "it": 0,
                "iot": 0,
                "cctv": 0,
                "ot": 0,
                "access": 0,
                "unknown": 0,
                "active_subnets": [],
                "active_vlans": []
            }
        }

    def _get_latest_history_file(self) -> Optional[Path]:
        if not self.history_dir.exists():
            return None
        files = sorted(self.history_dir.glob("snapshot_*.json"), key=os.path.getmtime, reverse=True)
        return files[0] if files else None

    def _read_json_file(self, path: Path, fallback: Any) -> Any:
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                return {"error": f"Failed to read datafile {path.name}: {str(e)}"}
        return fallback
