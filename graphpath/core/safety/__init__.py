"""
Project AETHERIS - Safety & Execution Boundary Subsystem
Enforces authorized engagement boundaries, SOC 2 compliance, and OT safety interlocks.
"""

from graphpath.core.safety.scope_guard import (
    ScopeAuthorizationGuard,
    ScopeViolationException,
    get_scope_guard,
    configure_scope_guard,
)

__all__ = [
    "ScopeAuthorizationGuard",
    "ScopeViolationException",
    "get_scope_guard",
    "configure_scope_guard",
]
