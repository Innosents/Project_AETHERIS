"""
Project AETHERIS - Scope Authorization Guard & Engagement Provenance Engine
Enforces SOC 2 Type II compliance, authorized CIDR allowlisting, granular compound
(CIDR, Port) DO-NOT-SCAN safety exclusions, and cryptographic engagement provenance.
"""

import hashlib
import ipaddress
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from graphpath.core.probers.sanitization import sanitize_prober_payload

logger = logging.getLogger("graphpath.core.safety.scope_guard")


class ScopeViolationException(PermissionError):
    """Raised when an operation attempts to probe an IP or port prohibited by ScopeAuthorizationGuard."""

    def __init__(self, target_ip: str, port: int = 0, reason: str = ""):
        self.target_ip = target_ip
        self.port = port
        self.reason = reason
        super().__init__(f"Scope Violation [{target_ip}:{port}]: {reason}")


def _collapse_and_sort_networks(
    nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]
) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """
    Supernets and deduplicates networks via ipaddress.collapse_addresses.
    Separates IPv4 and IPv6 to prevent TypeErrors, then sorts by prefix length descending.
    """
    ipv4_nets = [n for n in nets if n.version == 4]
    ipv6_nets = [n for n in nets if n.version == 6]

    collapsed_v4 = list(ipaddress.collapse_addresses(ipv4_nets))
    collapsed_v6 = list(ipaddress.collapse_addresses(ipv6_nets))

    all_collapsed = collapsed_v4 + collapsed_v6
    # Sort by prefix length descending for fastest/most specific matching first
    return sorted(all_collapsed, key=lambda n: n.prefixlen, reverse=True)


class ScopeAuthorizationGuard:
    """
    Deterministic execution boundary ensuring all network discovery, ARP sweeps,
    raw socket pulses, and deep probers operate exclusively within authorized CIDR boundaries.
    """

    def __init__(
        self,
        in_scope_cidrs: Optional[List[Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network]]] = None,
        auth_ref: Optional[str] = None,
        do_not_scan_cidrs: Optional[List[Union[str, Tuple[str, int], ipaddress.IPv4Network, ipaddress.IPv6Network]]] = None,
        port_exclusions: Optional[List[Tuple[Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network], int]]] = None,
        allow_loopback: bool = False,
        timestamp: Optional[float] = None,
    ):
        self.auth_ref = auth_ref or os.getenv("GRAPHPATH_AUTH_REF", "ENGAGEMENT-LOCAL-AUDIT")
        self.allow_loopback = allow_loopback
        self.created_at = round(timestamp if timestamp is not None else time.time(), 4)

        # 1. Parse in-scope CIDRs
        raw_in_scope: List[str] = []
        if in_scope_cidrs:
            for item in in_scope_cidrs:
                raw_in_scope.append(str(item).strip())

        env_scope = os.getenv("GRAPHPATH_AUTHORIZED_SCOPE", "")
        if env_scope:
            raw_in_scope.extend([c.strip() for c in env_scope.split(",") if c.strip()])

        parsed_in_scope: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for cidr in raw_in_scope:
            try:
                parsed_in_scope.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                logger.warning(f"[Scope Guard] Invalid in-scope CIDR {cidr}: {e}")

        self.in_scope_cidrs = _collapse_and_sort_networks(parsed_in_scope)

        # 2. Parse DO-NOT-SCAN exclusions (Network & Compound Network:Port)
        raw_exclusions: List[Any] = []
        if do_not_scan_cidrs:
            raw_exclusions.extend(do_not_scan_cidrs)

        env_exclusions = os.getenv("GRAPHPATH_DO_NOT_SCAN", "")
        if env_exclusions:
            raw_exclusions.extend([c.strip() for c in env_exclusions.split(",") if c.strip()])

        parsed_do_not_scan: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        parsed_port_exclusions: List[Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], int]] = []

        if port_exclusions:
            for net_item, p in port_exclusions:
                try:
                    net_obj = (
                        net_item
                        if isinstance(net_item, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                        else ipaddress.ip_network(str(net_item).strip(), strict=False)
                    )
                    parsed_port_exclusions.append((net_obj, int(p)))
                except Exception as e:
                    logger.warning(f"[Scope Guard] Invalid port exclusion {net_item}:{p}: {e}")

        for item in raw_exclusions:
            if isinstance(item, tuple) and len(item) == 2:
                try:
                    net_obj = (
                        item[0]
                        if isinstance(item[0], (ipaddress.IPv4Network, ipaddress.IPv6Network))
                        else ipaddress.ip_network(str(item[0]).strip(), strict=False)
                    )
                    parsed_port_exclusions.append((net_obj, int(item[1])))
                except Exception as e:
                    logger.warning(f"[Scope Guard] Invalid tuple exclusion {item}: {e}")
                continue

            item_str = str(item).strip()
            # Check for compound "CIDR:PORT" format (e.g. "192.168.1.50:502" or "10.0.0.0/8:102")
            if ":" in item_str and not item_str.startswith("fe80") and not item_str.startswith("::"):
                # Potential IPv4 CIDR:Port
                parts = item_str.rsplit(":", 1)
                try:
                    port_num = int(parts[1])
                    net_obj = ipaddress.ip_network(parts[0].strip(), strict=False)
                    parsed_port_exclusions.append((net_obj, port_num))
                    continue
                except (ValueError, IndexError):
                    pass

            try:
                parsed_do_not_scan.append(ipaddress.ip_network(item_str, strict=False))
            except ValueError as e:
                logger.warning(f"[Scope Guard] Invalid exclusion CIDR {item_str}: {e}")

        self.do_not_scan = _collapse_and_sort_networks(parsed_do_not_scan)
        self.port_exclusions = parsed_port_exclusions

        # 3. Compute Cryptographic Engagement Provenance
        self.provenance = self._compute_provenance()
        self.provenance_token: str = self.provenance["provenance_token"]
        self.provenance_digest: str = self.provenance["provenance_digest_sha256"]

    def _compute_provenance(self) -> Dict[str, Any]:
        """Computes deterministic SHA-256 provenance over authorization scope parameters."""
        sorted_in = sorted([str(n) for n in self.in_scope_cidrs])
        sorted_ex = sorted([str(n) for n in self.do_not_scan])
        sorted_port_ex = sorted([f"{str(n)}:{p}" for n, p in self.port_exclusions])

        canonical_dict = {
            "auth_ref": self.auth_ref,
            "in_scope_cidrs": sorted_in,
            "do_not_scan_cidrs": sorted_ex,
            "port_exclusions": sorted_port_ex,
            "timestamp": self.created_at,
        }
        serialized = json.dumps(canonical_dict, sort_keys=True)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        token = f"AETH-SCOPE-{digest[:16].upper()}"

        return {
            "provenance_token": token,
            "provenance_digest_sha256": digest,
            "auth_ref": self.auth_ref,
            "timestamp": self.created_at,
        }

    def is_permitted(self, target_ip: str, port: int = 0) -> Tuple[bool, str]:
        """
        Validates whether target IP and optional port are strictly permitted by engagement scope.
        Returns: (is_permitted: bool, reason: str)
        """
        if not target_ip:
            return False, "Target IP is empty or undefined."

        clean_ip = target_ip.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return False, f"Invalid IP address format: {target_ip}"

        # Check special reserved network boundaries
        if ip_obj.is_multicast:
            refusal = f"[Scope Refusal] BLOCKED: Multicast address ({clean_ip}) prohibited from direct probing."
            logger.warning(refusal)
            return False, refusal

        if clean_ip == "255.255.255.255":
            refusal = "[Scope Refusal] BLOCKED: Limited broadcast address (255.255.255.255) prohibited."
            logger.warning(refusal)
            return False, refusal

        if ip_obj.is_loopback:
            is_explicit_loopback = any(ip_obj in net for net in self.in_scope_cidrs)
            if not self.allow_loopback and not is_explicit_loopback:
                refusal = f"[Scope Refusal] BLOCKED: Loopback target ({clean_ip}) prohibited without explicit loopback authorization."
                logger.warning(refusal)
                return False, refusal

        # 1. Check DO-NOT-SCAN Network Exclusions (Highest Priority Interlock)
        for ex_net in self.do_not_scan:
            if ip_obj in ex_net:
                refusal = f"[Scope Refusal] BLOCKED: Target {clean_ip} is in DO-NOT-SCAN exclusion subnet ({ex_net})."
                logger.warning(refusal)
                return False, refusal

        # 2. Check Compound Port-Specific Exclusions
        if port > 0 and self.port_exclusions:
            for ex_net, ex_port in self.port_exclusions:
                if port == ex_port and ip_obj in ex_net:
                    refusal = f"[Scope Refusal] BLOCKED: Target {clean_ip}:{port} matches port-specific DO-NOT-SCAN exclusion ({ex_net}:{ex_port})."
                    logger.warning(refusal)
                    return False, refusal

        # 3. Check Authorized In-Scope Allowlist
        if self.in_scope_cidrs:
            in_scope = any(ip_obj in allowed_net for allowed_net in self.in_scope_cidrs)
            if not in_scope:
                refusal = f"[Scope Refusal] REFUSED: Target {clean_ip} is OUT OF SCOPE. Authorization Ref: {self.auth_ref}."
                logger.warning(refusal)
                return False, refusal

        return True, f"Permitted under Authorization Ref: {self.auth_ref}"

    def assert_permitted(self, target_ip: str, port: int = 0) -> None:
        """Enforces scope permission, raising ScopeViolationException on denial."""
        allowed, reason = self.is_permitted(target_ip, port)
        if not allowed:
            raise ScopeViolationException(target_ip=target_ip, port=port, reason=reason)

    def filter_in_scope_ips(self, ips: List[str], port: int = 0) -> List[str]:
        """Filters a collection of IP addresses to strictly those permitted by scope rules."""
        permitted = []
        for ip in ips:
            allowed, reason = self.is_permitted(ip, port)
            if allowed:
                permitted.append(ip)
            else:
                logger.debug(f"[Scope Filter] Dropped {ip}: {reason}")
        return permitted

    def get_scope_summary(self) -> Dict[str, Any]:
        """Returns structured metadata regarding active scope constraints for reports and audit ledgers."""
        summary = {
            "authorization_reference": self.auth_ref,
            "provenance_token": self.provenance_token,
            "provenance_digest_sha256": self.provenance_digest,
            "has_explicit_scope": len(self.in_scope_cidrs) > 0,
            "in_scope_cidrs": [str(net) for net in self.in_scope_cidrs],
            "do_not_scan_cidrs": [str(net) for net in self.do_not_scan],
            "port_exclusions": [f"{str(n)}:{p}" for n, p in self.port_exclusions],
            "total_authorized_subnets": len(self.in_scope_cidrs),
            "total_excluded_subnets": len(self.do_not_scan),
            "total_port_exclusions": len(self.port_exclusions),
            "allow_loopback": self.allow_loopback,
            "timestamp": self.created_at,
        }
        return sanitize_prober_payload(summary)


# Global singleton management
_scope_guard_instance: Optional[ScopeAuthorizationGuard] = None


def get_scope_guard() -> ScopeAuthorizationGuard:
    """Retrieves the global ScopeAuthorizationGuard singleton."""
    global _scope_guard_instance
    if _scope_guard_instance is None:
        _scope_guard_instance = ScopeAuthorizationGuard()
    return _scope_guard_instance


def configure_scope_guard(
    in_scope_cidrs: Optional[List[Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network]]] = None,
    auth_ref: Optional[str] = None,
    do_not_scan_cidrs: Optional[List[Union[str, Tuple[str, int], ipaddress.IPv4Network, ipaddress.IPv6Network]]] = None,
    port_exclusions: Optional[List[Tuple[Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network], int]]] = None,
    allow_loopback: bool = False,
    timestamp: Optional[float] = None,
) -> ScopeAuthorizationGuard:
    """Configures and resets the global ScopeAuthorizationGuard singleton."""
    global _scope_guard_instance
    _scope_guard_instance = ScopeAuthorizationGuard(
        in_scope_cidrs=in_scope_cidrs,
        auth_ref=auth_ref,
        do_not_scan_cidrs=do_not_scan_cidrs,
        port_exclusions=port_exclusions,
        allow_loopback=allow_loopback,
        timestamp=timestamp,
    )
    return _scope_guard_instance
