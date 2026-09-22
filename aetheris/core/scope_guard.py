"""
Project AETHERIS - Scope Guard Facade
Re-exports ScopeAuthorizationGuard, ScopeViolationException, ScopeGuard, and safety utilities.
"""

from aetheris.core.safety.scope_guard import (
    ScopeAuthorizationGuard,
    ScopeViolationException,
    ScopeGuard,
    get_scope_guard,
    configure_scope_guard,
    CognitiveSecurityFault,
    AetherisExecutionVisitor,
)
from aetheris.core.ports.scope_guard_port import (
    AstSecurityVisitorPort,
    MutationAuthorizationRequest,
    NetworkAuthorizationResult,
    ScopeAuditPolicy,
    ScopeGuardPort,
    SecurityEvaluationResult,
)

__all__ = [
    "ScopeAuthorizationGuard",
    "ScopeViolationException",
    "ScopeGuard",
    "get_scope_guard",
    "configure_scope_guard",
    "CognitiveSecurityFault",
    "AetherisExecutionVisitor",
    "ScopeGuardPort",
    "AstSecurityVisitorPort",
    "ScopeAuditPolicy",
    "MutationAuthorizationRequest",
    "SecurityEvaluationResult",
    "NetworkAuthorizationResult",
]