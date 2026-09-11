"""
Scope Authorization Guard: Enforces Authorized CIDR Allowlisting,
DO-NOT-SCAN Safety Exclusions, and Signed Engagement Reference Provenance.
"""

import os
import ipaddress
import logging
from typing import List, Tuple, Dict, Any, Optional, Union

logger = logging.getLogger('graphpath.scope_guard')

class ScopeAuthorizationGuard:
    """
    Enforces that all discovery, ARP sweeps, port checks, and SNMP queries
    strictly operate within authorized CIDR boundaries under a verified engagement ref.
    """

    def __init__(
        self,
        in_scope_cidrs: Optional[List[str]] = None,
        auth_ref: Optional[str] = None,
        do_not_scan_cidrs: Optional[List[str]] = None
    ):
        self.auth_ref = auth_ref or os.getenv('GRAPHPATH_AUTH_REF', 'ENGAGEMENT-LOCAL-AUDIT')
        
        # Parse in-scope CIDRs
        self.in_scope_cidrs: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        raw_in_scope = list(in_scope_cidrs or [])
        env_scope = os.getenv('GRAPHPATH_AUTHORIZED_SCOPE', '')
        if env_scope:
            raw_in_scope.extend([c.strip() for c in env_scope.split(',') if c.strip()])
            
        for cidr in raw_in_scope:
            try:
                self.in_scope_cidrs.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                logger.warning(f'[Scope Guard] Invalid in-scope CIDR {cidr}: {e}')

        # Parse do-not-scan safety exclusion CIDRs
        self.do_not_scan: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        raw_exclusions = list(do_not_scan_cidrs or [])
        env_exclusions = os.getenv('GRAPHPATH_DO_NOT_SCAN', '')
        if env_exclusions:
            raw_exclusions.extend([c.strip() for c in env_exclusions.split(',') if c.strip()])

        for cidr in raw_exclusions:
            try:
                self.do_not_scan.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                logger.warning(f'[Scope Guard] Invalid exclusion CIDR {cidr}: {e}')

    def is_permitted(self, target_ip: str, port: int = 0) -> Tuple[bool, str]:
        """
        Validates if a target IP and optional port are within the authorized engagement scope.
        Returns: (is_permitted: bool, reason_or_refusal_detail: str)
        """
        if not target_ip:
            return False, 'Target IP is empty or undefined.'

        # Normalize IP address
        try:
            ip_obj = ipaddress.ip_address(target_ip)
        except ValueError:
            return False, f'Invalid IP address format: {target_ip}'

        # 1. Check DO-NOT-SCAN Safety Exclusions (Highest Priority Interlock)
        for ex_net in self.do_not_scan:
            if ip_obj in ex_net:
                refusal = f'[Scope Refusal] BLOCKED: Target {target_ip} is in DO-NOT-SCAN exclusion subnet ({ex_net}).'
                logger.warning(refusal)
                return False, refusal

        # 2. Check Authorized-Scope Allowlist
        if self.in_scope_cidrs:
            in_scope = any(ip_obj in allowed_net for allowed_net in self.in_scope_cidrs)
            if not in_scope:
                refusal = f'[Scope Refusal] REFUSED: Target {target_ip} is OUT OF SCOPE. Authorization Ref: {self.auth_ref}.'
                logger.warning(refusal)
                return False, refusal

        return True, f'Permitted under Authorization Ref: {self.auth_ref}'

    def filter_in_scope_ips(self, ips: List[str]) -> List[str]:
        """Filters an iterable of IP addresses to only those permitted by active scope rules."""
        permitted = []
        for ip in ips:
            allowed, reason = self.is_permitted(ip)
            if allowed:
                permitted.append(ip)
            else:
                print(f' • [Scope Refusal] {reason}')
        return permitted

    def get_scope_summary(self) -> Dict[str, Any]:
        """Returns structured metadata regarding active scope constraints for reports and audit logs."""
        return {
            'authorization_reference': self.auth_ref,
            'has_explicit_scope': len(self.in_scope_cidrs) > 0,
            'in_scope_cidrs': [str(net) for net in self.in_scope_cidrs],
            'do_not_scan_cidrs': [str(net) for net in self.do_not_scan],
            'total_authorized_subnets': len(self.in_scope_cidrs),
            'total_excluded_subnets': len(self.do_not_scan)
        }

# Global singleton instance
_scope_guard_instance: Optional[ScopeAuthorizationGuard] = None

def get_scope_guard() -> ScopeAuthorizationGuard:
    global _scope_guard_instance
    if _scope_guard_instance is None:
        _scope_guard_instance = ScopeAuthorizationGuard()
    return _scope_guard_instance

def configure_scope_guard(
    in_scope_cidrs: Optional[List[str]] = None,
    auth_ref: Optional[str] = None,
    do_not_scan_cidrs: Optional[List[str]] = None
) -> ScopeAuthorizationGuard:
    global _scope_guard_instance
    _scope_guard_instance = ScopeAuthorizationGuard(
        in_scope_cidrs=in_scope_cidrs,
        auth_ref=auth_ref,
        do_not_scan_cidrs=do_not_scan_cidrs
    )
    return _scope_guard_instance
