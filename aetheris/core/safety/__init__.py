"""
Project AETHERIS - Safety & Execution Boundary Subsystem
Enforces authorized engagement boundaries, SOC 2 compliance, and OT safety interlocks.
"""

from .scope_guard import (
    ScopeAuthorizationGuard,
    ScopeViolationException,
    ScopeGuard,
    get_scope_guard,
    configure_scope_guard,
    CognitiveSecurityFault,
    AetherisExecutionVisitor,
)

__all__ = [
    "ScopeAuthorizationGuard",
    "ScopeViolationException",
    "ScopeGuard",
    "get_scope_guard",
    "configure_scope_guard",
    "CognitiveSecurityFault",
    "AetherisExecutionVisitor",
]
