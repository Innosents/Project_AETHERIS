"""
Unit test suite for BannerGrabPort and BannerGrabber adapter.
Validates AST boundary isolation, protocol conformance, and pure HTTP/TLS token parsing.
"""
import ast
import os
import pytest
from aetheris.core.ports.banner_grab_port import BannerGrabPort, BannerGrabResult, ParsedBannerTokens
from aetheris.discovery.banner_grab import BannerGrabber, grab_banner


def test_banner_grab_port_ast_boundary():
    """Verify banner_grab_port.py contains zero socket, ssl, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "banner_grab_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"socket", "ssl", "scapy", "subprocess", "sqlite3", "redis", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_banner_grabber_protocol_conformance():
    """Verify BannerGrabber satisfies BannerGrabPort protocol."""
    grabber = BannerGrabber()
    assert isinstance(grabber, BannerGrabPort)


def test_pure_http_descriptor_parsing():
    """Verify in-memory HTML title, server header, and cookie extraction."""
    raw_http_payload = (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.41 (Ubuntu)\r\n"
        "Set-Cookie: session_id=xyz789; Path=/; HttpOnly\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><head><title>Axis Network Camera - M3045</title></head><body></body></html>"
    )

    tokens = BannerGrabber.parse_http_descriptors(raw_http_payload)
    assert tokens.server == "Apache/2.4.41 (Ubuntu)"
    assert tokens.title == "Axis Network Camera - M3045"
    assert "session_id=xyz789" in tokens.cookie

    # Legacy mapping access verification
    assert tokens["server"] == "Apache/2.4.41 (Ubuntu)"
    assert tokens.get("title") == "Axis Network Camera - M3045"


def test_banner_grab_legacy_alias():
    """Verify top-level grab_banner functional entrypoint remains backward compatible."""
    # Test against unreachable loopback port to verify non-blocking graceful None return
    res = grab_banner("127.0.0.1", 65534, timeout=0.05)
    assert res is None or isinstance(res, str)
