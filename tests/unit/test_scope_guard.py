"""
Project AETHERIS - Unit Tests for Scope Authorization Guard & Engagement Provenance Engine
Verifies:
  - Default unconstrained allow-all behavior
  - Strict CIDR allowlist enforcement
  - DO-NOT-SCAN priority safety interlock
  - Granular compound (CIDR, Port) exclusions
  - Multicast, broadcast, loopback, and invalid IP boundary validation
  - Cryptographic engagement provenance token & SHA-256 digest determinism
  - Exception raising via assert_permitted
  - Network collapsing and prefix-length sorting
  - Batch candidate IP filtering
  - Singleton lifecycle and payload sanitization
"""

import json
from pathlib import Path
import pytest

from aetheris.core.safety import (
    ScopeAuthorizationGuard,
    ScopeViolationException,
    ScopeGuard,
    get_scope_guard,
    configure_scope_guard,
)


class TestScopeAuthorizationGuard:
    """Test suite for ScopeAuthorizationGuard."""

    def test_package_exports(self):
        """Verify core safety components are exported from aetheris.core.safety."""
        import aetheris.core.safety as safety
        assert hasattr(safety, "ScopeAuthorizationGuard")
        assert hasattr(safety, "ScopeViolationException")
        assert hasattr(safety, "ScopeGuard")
        assert hasattr(safety, "get_scope_guard")
        assert hasattr(safety, "configure_scope_guard")

    def test_default_unconstrained_allow_all(self):
        """When no in-scope CIDRs are configured, any valid non-excluded IP is permitted."""
        guard = ScopeAuthorizationGuard(
            in_scope_cidrs=[],
            do_not_scan_cidrs=["192.168.1.200/32"],
            auth_ref="ENG-UNCONSTRAINED"
        )
        assert guard.is_permitted("8.8.8.8")[0] is True
        assert guard.is_permitted("10.50.1.1")[0] is True
        assert guard.is_permitted("192.168.1.199")[0] is True
        assert guard.is_permitted("192.168.1.200")[0] is False

    def test_strict_cidr_allowlist_enforcement(self):
        """Targets outside the authorized CIDR set must be strictly refused."""
        guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["192.168.1.0/24", "10.0.0.0/16"],
            auth_ref="SOC2-ENG-9021"
        )

        # In-scope permitted
        allowed, reason = guard.is_permitted("192.168.1.25")
        assert allowed is True
        assert "SOC2-ENG-9021" in reason

        allowed_10, _ = guard.is_permitted("10.0.50.1")
        assert allowed_10 is True

        # Out-of-scope refused
        allowed_out, reason_out = guard.is_permitted("172.16.0.1")
        assert allowed_out is False
        assert "OUT OF SCOPE" in reason_out
        assert "SOC2-ENG-9021" in reason_out

    def test_do_not_scan_priority_interlock(self):
        """DO-NOT-SCAN exclusions must override all in-scope authorizations."""
        guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["192.168.1.0/24"],
            do_not_scan_cidrs=["192.168.1.50/32", "192.168.1.128/28"],
            auth_ref="ENG-CRITICAL-OT"
        )

        assert guard.is_permitted("192.168.1.49")[0] is True
        
        # Single IP exclusion
        allowed_50, reason_50 = guard.is_permitted("192.168.1.50")
        assert allowed_50 is False
        assert "DO-NOT-SCAN" in reason_50

        # Subnet exclusion block
        allowed_block, reason_block = guard.is_permitted("192.168.1.130")
        assert allowed_block is False
        assert "DO-NOT-SCAN" in reason_block

    def test_compound_port_specific_exclusions(self):
        """Test compound (CIDR, Port) exclusions: allow host ping, strictly block sensitive ports."""
        guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["192.168.1.0/24"],
            do_not_scan_cidrs=[
                "192.168.1.50:502",          # Block Modbus on specific host
                ("192.168.1.0/24", 102),     # Block Siemens S7Comm across entire subnet
            ],
            auth_ref="ENG-SAFETY-PORT"
        )

        # Host-level probe (port 0) is permitted
        assert guard.is_permitted("192.168.1.50", port=0)[0] is True
        # Web probe (port 80) is permitted
        assert guard.is_permitted("192.168.1.50", port=80)[0] is True

        # Modbus on 192.168.1.50 is BLOCKED
        allowed_modbus, reason_modbus = guard.is_permitted("192.168.1.50", port=502)
        assert allowed_modbus is False
        assert "port-specific DO-NOT-SCAN exclusion" in reason_modbus
        assert "502" in reason_modbus

        # Modbus on another host is permitted
        assert guard.is_permitted("192.168.1.51", port=502)[0] is True

        # S7Comm is blocked across entire 192.168.1.0/24
        assert guard.is_permitted("192.168.1.10", port=102)[0] is False
        assert guard.is_permitted("192.168.1.99", port=102)[0] is False

    def test_special_ip_handling(self):
        """Verify handling of multicast, broadcast, loopback, and malformed IP strings."""
        guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["192.168.1.0/24"],
            allow_loopback=False
        )

        # Multicast
        allowed_mcast, reason_mcast = guard.is_permitted("224.0.0.1")
        assert allowed_mcast is False
        assert "Multicast" in reason_mcast

        # Broadcast
        allowed_bcast, reason_bcast = guard.is_permitted("255.255.255.255")
        assert allowed_bcast is False
        assert "broadcast" in reason_bcast.lower()

        # Loopback rejected by default
        allowed_loop, reason_loop = guard.is_permitted("127.0.0.1")
        assert allowed_loop is False
        assert "Loopback" in reason_loop

        # Loopback permitted when allow_loopback=True
        guard_loop = ScopeAuthorizationGuard(allow_loopback=True)
        assert guard_loop.is_permitted("127.0.0.1")[0] is True

        # Malformed strings
        assert guard.is_permitted("")[0] is False
        assert guard.is_permitted("not_an_ip")[0] is False
        assert guard.is_permitted("999.999.999.999")[0] is False

    def test_cryptographic_provenance_token(self):
        """Assert deterministic SHA-256 provenance token generation."""
        fixed_ts = 1700000000.0
        guard1 = ScopeAuthorizationGuard(
            in_scope_cidrs=["192.168.1.0/24"],
            do_not_scan_cidrs=["192.168.1.100/32"],
            auth_ref="ENG-PROVENANCE-TEST",
            timestamp=fixed_ts
        )
        guard2 = ScopeAuthorizationGuard(
            in_scope_cidrs=["192.168.1.0/24"],
            do_not_scan_cidrs=["192.168.1.100/32"],
            auth_ref="ENG-PROVENANCE-TEST",
            timestamp=fixed_ts
        )

        assert guard1.provenance_token.startswith("AETH-SCOPE-")
        assert len(guard1.provenance_digest) == 64  # SHA-256 hex string
        assert guard1.provenance_token == guard2.provenance_token
        assert guard1.provenance_digest == guard2.provenance_digest

    def test_assert_permitted_raises_exception(self):
        """Assert assert_permitted raises ScopeViolationException on unauthorized targets."""
        guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["10.0.0.0/8"],
            do_not_scan_cidrs=["10.1.1.1/32"]
        )

        # In-scope: does not raise
        guard.assert_permitted("10.0.0.1", port=80)

        # Out-of-scope raises ScopeViolationException
        with pytest.raises(ScopeViolationException) as exc_info:
            guard.assert_permitted("192.168.1.1", port=443)
        assert "OUT OF SCOPE" in str(exc_info.value)
        assert exc_info.value.target_ip == "192.168.1.1"
        assert exc_info.value.port == 443

        # Excluded raises ScopeViolationException
        with pytest.raises(ScopeViolationException):
            guard.assert_permitted("10.1.1.1")

    def test_ip_collapse_and_sorting(self):
        """Verify contiguous subnets are collapsed and sorted by prefix length."""
        guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["10.0.0.0/24", "10.0.1.0/24", "192.168.1.0/28", "192.168.1.16/28"],
        )
        # Contiguous /24s collapse to /23: 10.0.0.0/23
        # Contiguous /28s collapse to /27: 192.168.1.0/27
        summary = guard.get_scope_summary()
        cidrs = summary["in_scope_cidrs"]
        assert "10.0.0.0/23" in cidrs
        assert "192.168.1.0/27" in cidrs

    def test_filter_in_scope_ips_batch(self):
        """Verify batch filtering of candidate IP lists."""
        guard = ScopeAuthorizationGuard(
            in_scope_cidrs=["192.168.1.0/24"],
            do_not_scan_cidrs=["192.168.1.50/32"]
        )
        candidates = ["192.168.1.1", "192.168.1.50", "10.0.0.1", "192.168.1.20", "224.0.0.1"]
        filtered = guard.filter_in_scope_ips(candidates)
        assert filtered == ["192.168.1.1", "192.168.1.20"]

    def test_singleton_and_payload_sanitization(self):
        """Verify singleton configure lifecycle and JSON round-trip invariance."""
        configured = configure_scope_guard(
            in_scope_cidrs=["172.16.0.0/16"],
            auth_ref="ENG-SINGLETON-CHECK",
            do_not_scan_cidrs=["172.16.100.0/24:502"]
        )
        retrieved = get_scope_guard()
        assert retrieved is configured
        assert retrieved.auth_ref == "ENG-SINGLETON-CHECK"

        summary = configured.get_scope_summary()
        serialized = json.dumps(summary)
        deserialized = json.loads(serialized)
        assert deserialized == summary

        for k, v in summary.items():
            assert not isinstance(v, bytes), f"Key {k} contains raw bytes: {v}"


class TestScopeGuardAstMutation:
    """Validates AST target path authorization across hexagonal layers."""

    def test_authorized_ast_targets_list(self):
        guard = ScopeGuard()
        expected = {
            Path("aetheris/core/ports"),
            Path("aetheris/core/parsers"),
            Path("aetheris/infrastructure/adapters"),
            Path("aetheris/discovery"),
        }
        assert set(guard.authorized_ast_targets) == expected
        assert set(ScopeGuard.AUTHORIZED_AST_TARGETS) == expected

    def test_authorize_module_mutation_hexagonal_layers(self):
        # Ports
        assert ScopeGuard.authorize_module_mutation("aetheris/core/ports/l7_ics_inbound.py") is True
        assert ScopeGuard.authorize_module_mutation(Path("aetheris/core/ports/l2_span_inbound.py")) is True

        # Parsers
        assert ScopeGuard.authorize_module_mutation("aetheris/core/parsers/industrial_parser.py") is True
        assert ScopeGuard.authorize_module_mutation("aetheris/core/parsers/chassis_parser.py") is True

        # Adapters
        assert ScopeGuard.authorize_module_mutation("aetheris/infrastructure/adapters/modbus_adapter.py") is True
        assert ScopeGuard.authorize_module_mutation("aetheris/infrastructure/adapters/span_tap_adapter.py") is True

        # Discovery
        assert ScopeGuard.authorize_module_mutation("aetheris/discovery/advanced_spatial_prober.py") is True
        assert ScopeGuard.authorize_module_mutation("aetheris/discovery/mirror_engine.py") is True

    def test_authorize_module_mutation_authorized_domains(self):
        # Existing authorized domains: l2_physical, l3_network, hardware_telemetry, self_healing
        assert ScopeGuard.authorize_module_mutation("subsystem/l2_physical/test_runner.py") is True
        assert ScopeGuard.authorize_module_mutation("custom/l3_network/routing.py") is True
        assert ScopeGuard.authorize_module_mutation("plugins/hardware_telemetry/power.py") is True
        assert ScopeGuard.authorize_module_mutation("engine/self_healing/agent.py") is True

    def test_authorize_module_mutation_prohibited_targets(self):
        # Purged core/probers is no longer authorized
        assert ScopeGuard.authorize_module_mutation("aetheris/core/probers/bacnet_probe.py") is False

        # Non-python extensions rejected
        assert ScopeGuard.authorize_module_mutation("aetheris/core/parsers/chassis_parser.json") is False
        assert ScopeGuard.authorize_module_mutation("aetheris/infrastructure/adapters/script.sh") is False

        # Arbitrary and safety-critical paths rejected
        assert ScopeGuard.authorize_module_mutation("aetheris/core/safety/scope_guard.py") is False
        assert ScopeGuard.authorize_module_mutation("/etc/shadow.py") is False
        assert ScopeGuard.authorize_module_mutation("C:/Windows/System32/calc.py") is False

