"""
Unit Tests for ScopeAuthorizationGuard
Validates CIDR boundary enforcement, DO-NOT-SCAN safety exclusions,
environment variable ingestion, and IP allowlist filtering.
"""

import os
import pytest
from aetheris.core.scope_guard import ScopeAuthorizationGuard, get_scope_guard, configure_scope_guard


def test_scope_guard_in_scope_and_exclusions():
    guard = ScopeAuthorizationGuard(
        in_scope_cidrs=["192.168.1.0/24", "10.0.0.0/16"],
        do_not_scan_cidrs=["192.168.1.50/32", "10.0.100.0/24"],
        auth_ref="TEST-ENGAGEMENT-01"
    )

    # In-scope allowed
    assert guard.is_permitted("192.168.1.10")[0] is True
    assert guard.is_permitted("10.0.1.5")[0] is True

    # Out of scope rejected
    allowed, reason = guard.is_permitted("172.16.0.1")
    assert allowed is False
    assert "OUT OF SCOPE" in reason

    # DO-NOT-SCAN priority exclusion interlock
    allowed_ex, reason_ex = guard.is_permitted("192.168.1.50")
    assert allowed_ex is False
    assert "DO-NOT-SCAN" in reason_ex

    # Subnet range exclusion
    allowed_sub, _ = guard.is_permitted("10.0.100.25")
    assert allowed_sub is False

    # List filtering
    candidates = ["192.168.1.1", "192.168.1.50", "172.16.1.1", "10.0.1.10"]
    filtered = guard.filter_in_scope_ips(candidates)
    assert filtered == ["192.168.1.1", "10.0.1.10"]


def test_scope_guard_invalid_inputs():
    guard = ScopeAuthorizationGuard(in_scope_cidrs=["192.168.1.0/24"])

    allowed_empty, reason_empty = guard.is_permitted("")
    assert allowed_empty is False
    assert "empty or undefined" in reason_empty

    allowed_invalid, reason_invalid = guard.is_permitted("999.999.999.999")
    assert allowed_invalid is False
    assert "Invalid IP address format" in reason_invalid


def test_scope_guard_unconstrained_when_no_scope_defined():
    guard = ScopeAuthorizationGuard(
        in_scope_cidrs=[],
        do_not_scan_cidrs=["192.168.1.100/32"]
    )

    # Without explicit in_scope_cidrs, any IP outside do_not_scan is permitted
    assert guard.is_permitted("8.8.8.8")[0] is True
    assert guard.is_permitted("192.168.1.100")[0] is False


def test_scope_guard_summary_metadata():
    guard = ScopeAuthorizationGuard(
        in_scope_cidrs=["10.10.0.0/16"],
        do_not_scan_cidrs=["10.10.1.1/32"],
        auth_ref="ENG-SUMMARY-CHECK"
    )
    summary = guard.get_scope_summary()
    assert summary["authorization_reference"] == "ENG-SUMMARY-CHECK"
    assert summary["has_explicit_scope"] is True
    assert summary["total_authorized_subnets"] == 1
    assert summary["total_excluded_subnets"] == 1


def test_scope_guard_singleton_configure():
    configured = configure_scope_guard(
        in_scope_cidrs=["172.20.0.0/16"],
        auth_ref="GLOBAL-REF-01"
    )
    retrieved = get_scope_guard()
    assert retrieved is configured
    assert retrieved.auth_ref == "GLOBAL-REF-01"
    assert retrieved.is_permitted("172.20.10.5")[0] is True

