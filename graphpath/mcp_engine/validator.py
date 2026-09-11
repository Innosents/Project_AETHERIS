"""
Validation Guard Engine
Executes strict schema checks, Pydantic model validation, SNMP OID uniqueness audits,
DIP profile integrity checks, and AST code syntax contract gates.
"""

import os
import ast
import json
import inspect
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from pydantic import ValidationError

from mcp_engine.validation_models import (
    NodeModel,
    EdgeModel,
    SummaryModel,
    TopologyPayloadModel,
    DIPProfileModel,
    OIDModel,
    VALID_DEVICE_TYPES
)

BASE_DIR = Path(__file__).resolve().parent.parent

class ValidationGuardEngine:
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or BASE_DIR
        self.dip_path = self.base_dir / "device_identity_profiles.json"
        self.env_path = self.base_dir / "environment_profiles.json"

    def validate_topology_schema(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates complete network topology JSON payloads against TopologyPayloadModel.
        """
        if not payload or not isinstance(payload, dict):
            return {
                "status": "failed",
                "valid": False,
                "total_errors": 1,
                "errors": [{"loc": ["payload"], "msg": "Payload must be a non-empty JSON object", "type": "type_error"}]
            }

        try:
            model = TopologyPayloadModel.model_validate(payload)
            return {
                "status": "passed",
                "valid": True,
                "total_errors": 0,
                "node_count": len(model.nodes),
                "edge_count": len(model.edges),
                "active_subnets": model.summary.active_subnets if model.summary else [],
                "summary": model.summary.model_dump() if model.summary else {}
            }
        except ValidationError as e:
            formatted_errors = []
            for err in e.errors():
                formatted_errors.append({
                    "loc": [str(x) for x in err.get("loc", [])],
                    "msg": err.get("msg", "Validation error"),
                    "type": err.get("type", "value_error"),
                    "input": str(err.get("input", ""))[:100]
                })

            return {
                "status": "failed",
                "valid": False,
                "total_errors": len(formatted_errors),
                "errors": formatted_errors,
                "node_count": len(payload.get("nodes", [])),
                "edge_count": len(payload.get("edges", []))
            }

    def check_node_integrity(self, node_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates an individual network device node against NodeModel.
        """
        if not node_data or not isinstance(node_data, dict):
            return {
                "status": "failed",
                "valid": False,
                "errors": [{"msg": "Node data must be a dictionary."}]
            }

        try:
            node = NodeModel.model_validate(node_data)
            return {
                "status": "passed",
                "valid": True,
                "node_id": node.id,
                "validated_node": node.model_dump()
            }
        except ValidationError as e:
            formatted_errors = []
            for err in e.errors():
                formatted_errors.append({
                    "field": ".".join(str(x) for x in err.get("loc", [])),
                    "msg": err.get("msg", ""),
                    "input": err.get("input")
                })
            return {
                "status": "failed",
                "valid": False,
                "node_id": node_data.get("id", "unknown"),
                "total_errors": len(formatted_errors),
                "errors": formatted_errors
            }

    def verify_oid_uniqueness(self, custom_oids: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Audits all Object Identifiers (OIDs) across oid_library.py and custom tables.
        Verifies ASN.1 syntax, uniqueness, and detects collisions.
        """
        all_oids: List[Dict[str, Any]] = []

        # 1. Inspect core IndustrialEnterpriseOIDs & StandardOIDs
        try:
            from discovery.oid_library import StandardOIDs, IndustrialEnterpriseOIDs
            
            # Standard MIB-II base attributes
            for attr in dir(StandardOIDs):
                if attr.isupper() and not attr.startswith("_") and attr != "ENTERPRISE_MAP":
                    val = getattr(StandardOIDs, attr)
                    if isinstance(val, str):
                        all_oids.append({
                            "oid": val,
                            "name": attr,
                            "vendor": "generic_mib2",
                            "source": "StandardOIDs"
                        })

            # Enterprise getters
            all_oids.extend(IndustrialEnterpriseOIDs.get_siemens_s7_oids())
            all_oids.extend(IndustrialEnterpriseOIDs.get_schneider_pac_oids())
            all_oids.extend(IndustrialEnterpriseOIDs.get_rockwell_micro850_oids())
            all_oids.extend(IndustrialEnterpriseOIDs.get_rockwell_panelview_oids())
            all_oids.extend(IndustrialEnterpriseOIDs.get_mercury_access_oids())
            all_oids.extend(IndustrialEnterpriseOIDs.get_moxa_switch_oids())
            all_oids.extend(IndustrialEnterpriseOIDs.get_cisco_poe_switch_oids("192.168.1.1", "Catalyst 9300"))
            all_oids.extend(IndustrialEnterpriseOIDs.get_axis_camera_oids("M3046-V", {}, {}, 12.5))
            all_oids.extend(IndustrialEnterpriseOIDs.get_avigilon_nvr_oids("ACC ES HD", {}, 200.0, "NVR-02"))
        except Exception as e:
            return {"status": "error", "message": f"Failed to load oid_library: {e}", "valid": False}

        # 2. Append any custom OIDs
        if custom_oids:
            for item in custom_oids:
                all_oids.append(item)

        # 3. Perform Validation and Collision Detection
        seen_oids: Dict[str, List[Dict[str, Any]]] = {}
        syntax_errors: List[Dict[str, Any]] = []
        collisions: List[Dict[str, Any]] = []

        for item in all_oids:
            oid_str = item.get("oid", "").strip()
            name_str = item.get("name", "").strip()

            # Syntax validation via OIDModel
            try:
                OIDModel(oid=oid_str, name=name_str, vendor=item.get("vendor", ""))
            except ValidationError as ve:
                syntax_errors.append({
                    "oid": oid_str,
                    "name": name_str,
                    "vendor": item.get("vendor"),
                    "error": str(ve.errors()[0].get("msg"))
                })
                continue

            # Collision tracking
            if oid_str in seen_oids:
                seen_oids[oid_str].append(item)
            else:
                seen_oids[oid_str] = [item]

        for oid_val, entries in seen_oids.items():
            if len(entries) > 1:
                # Filter non-standard-constant entries
                real_entries = [e for e in entries if e.get("source") != "StandardOIDs"]
                if len(real_entries) > 1:
                    vendors = list(set(e.get("vendor") for e in real_entries if e.get("vendor")))
                    names = list(set(e.get("name") for e in real_entries))
                    if len(names) > 1 or len(vendors) > 1:
                        collisions.append({
                            "oid": oid_val,
                            "collision_count": len(entries),
                            "conflicting_entries": entries
                        })
                elif len(real_entries) == 0:
                    names = list(set(e.get("name") for e in entries))
                    if len(names) > 1:
                        collisions.append({
                            "oid": oid_val,
                            "collision_count": len(entries),
                            "conflicting_entries": entries
                        })

        is_valid = len(syntax_errors) == 0 and len(collisions) == 0

        return {
            "status": "passed" if is_valid else "failed",
            "valid": is_valid,
            "total_oids_audited": len(all_oids),
            "unique_oids_count": len(seen_oids),
            "syntax_error_count": len(syntax_errors),
            "syntax_errors": syntax_errors,
            "collision_count": len(collisions),
            "collisions": collisions
        }

    def audit_dip_configuration(self, profiles_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Audits device_identity_profiles.json against schema rules.
        """
        target_path = Path(profiles_path) if profiles_path else self.dip_path

        if not target_path.exists():
            return {
                "status": "passed",
                "valid": True,
                "message": f"DIP database {target_path.name} is empty/not created yet.",
                "total_profiles": 0,
                "violations": []
            }

        try:
            with target_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return {
                "status": "failed",
                "valid": False,
                "message": f"Failed to parse DIP JSON file: {e}",
                "violations": [{"profile_id": "file", "error": str(e)}]
            }

        total_profiles = len(data)
        violations = []
        locked_count = 0

        for profile_id, prof in data.items():
            if not isinstance(prof, dict):
                violations.append({"profile_id": profile_id, "error": "Profile entry is not a JSON object."})
                continue

            # Ensure profile_id matches dictionary key
            if "profile_id" not in prof:
                prof["profile_id"] = profile_id

            if prof.get("is_locked"):
                locked_count += 1

            try:
                DIPProfileModel.model_validate(prof)
            except ValidationError as ve:
                for err in ve.errors():
                    violations.append({
                        "profile_id": profile_id,
                        "field": ".".join(str(x) for x in err.get("loc", [])),
                        "error": err.get("msg", "Validation error"),
                        "input": err.get("input")
                    })

        is_valid = len(violations) == 0
        compliance_pct = round(100.0 * (total_profiles - len(violations)) / max(1, total_profiles), 1)

        return {
            "status": "passed" if is_valid else "failed",
            "valid": is_valid,
            "compliance_score_percent": max(0.0, compliance_pct),
            "total_profiles_audited": total_profiles,
            "locked_profiles_count": locked_count,
            "violation_count": len(violations),
            "violations": violations
        }

    def run_contract_check(self, file_paths: Optional[List[str]] = None, strict: bool = False) -> Dict[str, Any]:
        """
        Syntax gate and code contract checker.
        Parses Python files into AST to detect syntax errors before commit.
        """
        if file_paths:
            targets = [Path(p) if Path(p).is_absolute() else (self.base_dir / p) for p in file_paths]
        else:
            # Default to inspecting core GraphPath source files
            targets = list(self.base_dir.glob("**/*.py"))
            # Filter out virtual environment
            targets = [p for p in targets if "venv" not in p.parts and ".git" not in p.parts]

        syntax_errors = []
        clean_files = []

        for p in targets:
            if not p.exists() or not p.is_file():
                continue

            def _format_path(path_obj: Path) -> str:
                try:
                    return str(path_obj.relative_to(self.base_dir))
                except ValueError:
                    return str(path_obj)

            try:
                with p.open("r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                ast.parse(content, filename=str(p))
                clean_files.append(_format_path(p))
            except SyntaxError as se:
                syntax_errors.append({
                    "file": _format_path(p),
                    "line": se.lineno,
                    "offset": se.offset,
                    "error": se.msg,
                    "text": se.text.strip() if se.text else ""
                })
            except Exception as e:
                syntax_errors.append({
                    "file": _format_path(p),
                    "error": f"Failed to read/parse: {str(e)}"
                })

        is_passed = len(syntax_errors) == 0

        return {
            "status": "passed" if is_passed else "failed",
            "gate_passed": is_passed,
            "total_files_checked": len(targets),
            "clean_files_count": len(clean_files),
            "syntax_error_count": len(syntax_errors),
            "syntax_errors": syntax_errors
        }

    def check_ot_probe_safety(
        self,
        ip: str,
        port: int,
        dev_type: str = "",
        subnet_cidr: str = "",
        do_not_scan_subnets: Optional[List[str]] = None,
        allow_industrial_probing: bool = False
    ) -> Dict[str, Any]:
        """
        [IEC 62443 / ISA-99 OT Safety Interlock]
        Verifies whether an IP target or network port is safe to probe.
        Prevents disruptive active sweeps on sensitive PLC, DCS, SCADA, or medical subnets.
        """
        import ipaddress

        # 1. Check Subnet Exclusion List
        excluded_subnets = list(do_not_scan_subnets or [])
        # Check environment profiles for do_not_scan markers
        try:
            if self.env_path.exists():
                with open(self.env_path, "r", encoding="utf-8") as f:
                    env_data = json.load(f)
                    for prof in env_data.get("profiles", []):
                        if prof.get("do_not_scan") or prof.get("safety_critical"):
                            excluded_subnets.append(prof.get("subnet"))
        except Exception:
            pass

        for ex in excluded_subnets:
            if not ex:
                continue
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(ex, strict=False):
                    return {
                        "safe": False,
                        "status": "blocked",
                        "reason": f"Target {ip} belongs to excluded/safety-critical subnet {ex}",
                        "action": "HALT_PROBE"
                    }
            except ValueError:
                pass

        # 2. Check Sensitive OT Fieldbus & Medical Ports
        SENSITIVE_INDUSTRIAL_PORTS = {
            502: "Modbus/TCP (PLC Fieldbus)",
            102: "Siemens S7comm / ISO-TSAP",
            44818: "EtherNet/IP CIP (Rockwell/Allen-Bradley)",
            47808: "BACnet/IP (Building Automation)",
            20000: "DNP3 (Substation SCADA)",
            2404: "IEC 60870-5-104 (Power Grid Telecontrol)",
            4840: "OPC UA (Industrial Interoperability)",
            23001: "Mercury Security Access Protocol (PACS Core)"
        }

        if port in SENSITIVE_INDUSTRIAL_PORTS:
            if not allow_industrial_probing:
                return {
                    "safe": False,
                    "status": "restricted",
                    "port": port,
                    "protocol": SENSITIVE_INDUSTRIAL_PORTS[port],
                    "reason": f"Port {port} ({SENSITIVE_INDUSTRIAL_PORTS[port]}) is an OT industrial interface. Aggressive probing blocked without explicit OT authorization flag.",
                    "action": "RESTRICT_TO_PASSIVE"
                }

        # 3. Check Known Sensitive Device Types
        if dev_type in ("plc", "safety_plc", "sis", "medical_device", "ventilator", "infusion_pump"):
            if not allow_industrial_probing:
                return {
                    "safe": False,
                    "status": "blocked",
                    "device_type": dev_type,
                    "reason": f"Device {ip} classified as sensitive life-safety/OT equipment ({dev_type}). Active interrogation halted.",
                    "action": "HALT_PROBE"
                }

        return {
            "safe": True,
            "status": "permitted",
            "reason": "Target passed IEC 62443 / ISA-99 Safety Interlock validation.",
            "action": "PROCEED"
        }

    def is_target_safe_for_probing(
        self,
        ip: str,
        port: int = 0,
        dev_type: str = "",
        subnet_cidr: str = "",
        do_not_scan_subnets: Optional[List[str]] = None,
        allow_industrial: bool = False
    ) -> bool:
        """Convenience boolean helper for inline probe gating."""
        res = self.check_ot_probe_safety(
            ip, port, dev_type, subnet_cidr,
            do_not_scan_subnets=do_not_scan_subnets,
            allow_industrial_probing=allow_industrial
        )
        return res.get("safe", False)
