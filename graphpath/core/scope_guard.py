"""
Project AETHERIS - Forwarding shim for Scope Authorization Guard.
Canonical implementation located in graphpath.core.safety.scope_guard.
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
