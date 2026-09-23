from unittest.mock import patch

from aetheris.core.ports.active_service_probe_port import (
    ActiveServiceProbePort,
    DiscoveredServiceEndpoint,
    StealthProbeSummary,
)
from aetheris.discovery.active_service_probe import ActiveServiceProber


def test_active_service_prober_conforms_to_port():
    prober = ActiveServiceProber()

    assert isinstance(prober, ActiveServiceProbePort)


def test_payload_parsers_are_socket_independent_and_preserve_heuristics():
    mdns = ActiveServiceProber._parse_mdns_payload(b"Samsung Tizen TV")
    ssdp = ActiveServiceProber._parse_ssdp_payload(
        "HTTP/1.1 200 OK\r\nServer: Roku/13\r\nST: mediarenderer\r\n"
    )

    assert mdns is not None
    assert mdns["vendor"] == "Samsung Electronics"
    assert mdns["type"] == "smart_tv"
    assert ssdp is not None
    assert ssdp["vendor"] == "Roku Inc."
    assert ssdp["server_header"] == "Roku/13"


def test_multicast_socket_creation_failures_return_empty_lists():
    prober = ActiveServiceProber()

    with patch(
        "aetheris.discovery.active_service_probe.socket.socket",
        side_effect=PermissionError,
    ):
        assert prober.probe_mdns() == []
        assert prober.probe_ssdp() == []


def test_unicast_and_stealth_results_use_port_models():
    prober = ActiveServiceProber()

    with patch.object(
        prober,
        "probe_netbios",
        return_value=DiscoveredServiceEndpoint(
            ip="192.0.2.10",
            hostname="TEST-TV",
            vendor="Samsung Electronics",
            type="smart_tv",
            model="Samsung Tizen Smart TV",
            source="netbios_137",
        ),
    ), patch.object(prober, "probe_ws_discovery", return_value=None), patch.object(
        prober, "probe_llmnr", return_value=None
    ), patch.object(prober, "probe_intel_amt", return_value=None):
        result = prober.probe_stealth_endpoint("192.0.2.10")

    assert isinstance(result, StealthProbeSummary)
    assert result.hostname == "TEST-TV"
    assert result.stealth_probes["netbios_137"]["vendor"] == "Samsung Electronics"