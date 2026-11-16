"""Adapter nmap i runner: parser, budowa argumentów, kontrakt ScopedTarget."""

from __future__ import annotations

import pytest

from app.core.scope_guard import Intrusiveness, ScopeConfig, ScopeGuard
from app.scanners.nmap import NmapAdapter, parse_nmap_xml
from app.scanners.runner import SubprocessRunner, ToolError, build_argv
from tests.conftest import FakeResolver, MemoryAudit
from tests.scanner_fakes import FakeRunner, fixture

SCOPE = {"allow": {"cidrs": ["172.30.99.0/24"]}, "deny": {"cidrs": ["172.30.99.1/32"]}}


@pytest.fixture
def guard(audit_sink: MemoryAudit) -> ScopeGuard:
    return ScopeGuard(ScopeConfig.from_dict(SCOPE), audit=audit_sink, resolver=FakeResolver())


def test_parse_discovery_returns_only_hosts_that_are_up() -> None:
    hosts = parse_nmap_xml(fixture("nmap_discovery.xml"))
    assert [h.ip for h in hosts] == ["172.30.99.10", "172.30.99.11", "172.30.99.14"]


def test_parse_services_keeps_open_ports_with_product_version_and_cpe() -> None:
    (host,) = parse_nmap_xml(fixture("nmap_services_httpd.xml"))
    assert host.ip == "172.30.99.10"
    assert host.hostname == "web-01.demo.lab"
    assert [s.port for s in host.services] == [80, 6379, 3000]
    httpd = host.services[0]
    assert (httpd.product, httpd.version, httpd.extrainfo) == ("Apache httpd", "2.4.49", "(Unix)")
    assert httpd.cpes == ("cpe:/a:apache:http_server:2.4.49",)
    assert httpd.banner == "Apache httpd 2.4.49 (Unix)"
    unknown = host.services[2]
    assert (unknown.product, unknown.version, unknown.cpes) == ("", "", ())


@pytest.mark.parametrize(
    "xml",
    ["", "to nie jest xml", "<html></html>", "<nmaprun><host><status state='up'/></host>"],
)
def test_parse_rejects_malformed_output(xml: str) -> None:
    with pytest.raises(ToolError):
        parse_nmap_xml(xml)


def test_parse_rejects_entity_expansion() -> None:
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;">]><nmaprun>&lol2;</nmaprun>'
    )
    with pytest.raises(ToolError, match="nieprawidłowy XML"):
        parse_nmap_xml(bomb)


def test_discover_passes_network_and_exclusions(guard: ScopeGuard) -> None:
    runner = FakeRunner(lambda _argv: fixture("nmap_discovery.xml"))
    network = guard.authorize_network(
        "172.30.99.0/24",
        tool="nmap_discovery",
        intrusiveness=Intrusiveness.LIGHT,
        rule_name="scope_sweep",
    )
    hosts = NmapAdapter(runner).discover(network)
    assert len(hosts) == 3
    (argv,) = runner.calls
    assert argv[0] == "nmap"
    assert argv[-2:] == ("--", "172.30.99.0/24")
    assert argv[argv.index("--exclude") + 1] == "172.30.99.1/32"
    assert "-sn" in argv


def test_scan_services_targets_only_the_authorised_address(guard: ScopeGuard) -> None:
    runner = FakeRunner(lambda _argv: fixture("nmap_services_httpd.xml"))
    target = guard.authorize(
        "172.30.99.10",
        tool="nmap_services",
        intrusiveness=Intrusiveness.LIGHT,
        rule_name="new_host_service_scan",
    )
    scan = NmapAdapter(runner).scan_services(target)
    assert scan.ip == "172.30.99.10"
    assert len(scan.services) == 3
    (argv,) = runner.calls
    assert argv[-2:] == ("--", "172.30.99.10")
    assert "-sV" in argv
    assert "--script" not in argv


def test_scan_ignores_results_for_other_hosts(guard: ScopeGuard) -> None:
    """Narzędzie zwróciło dane innego hosta niż cel: nie trafiają do wyniku."""
    runner = FakeRunner(lambda _argv: fixture("nmap_services_httpd.xml"))
    target = guard.authorize(
        "172.30.99.20", tool="nmap_services", intrusiveness=Intrusiveness.LIGHT, rule_name="r"
    )
    scan = NmapAdapter(runner).scan_services(target)
    assert scan.ip == "172.30.99.20"
    assert scan.services == ()


@pytest.mark.parametrize("value", ["172.30.99.10", None, {"ip": "172.30.99.10"}])
def test_adapter_rejects_targets_not_issued_by_scope_guard(value: object) -> None:
    adapter = NmapAdapter(FakeRunner(lambda _argv: ""))
    with pytest.raises(TypeError):
        adapter.scan_services(value)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        adapter.discover(value)  # type: ignore[arg-type]


def test_runner_rejects_plain_targets_and_unknown_binaries(guard: ScopeGuard) -> None:
    target = guard.authorize(
        "172.30.99.10", tool="x", intrusiveness=Intrusiveness.LIGHT, rule_name="r"
    )
    with pytest.raises(TypeError, match="scope_guard"):
        build_argv("nmap", ["-sV"], "172.30.99.10")  # type: ignore[arg-type]
    with pytest.raises(ToolError, match="dozwolonych"):
        build_argv("bash", ["-c", "id"], target)
    with pytest.raises(ToolError):
        build_argv("nmap", ["-sV\n8.8.8.8"], target)
    assert build_argv("nmap", ["-sV"], target) == ("nmap", "-sV", "--", "172.30.99.10")


@pytest.mark.parametrize("ports", ["80;id", "top-0", "top-99999", "", "80 443"])
def test_invalid_port_specs_are_rejected(guard: ScopeGuard, ports: str) -> None:
    target = guard.authorize(
        "172.30.99.10", tool="x", intrusiveness=Intrusiveness.LIGHT, rule_name="r"
    )
    with pytest.raises((ToolError, ValueError)):
        NmapAdapter(FakeRunner(lambda _argv: "")).scan_services(target, ports=ports)


def test_missing_binary_is_reported(guard: ScopeGuard, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    target = guard.authorize(
        "172.30.99.10", tool="x", intrusiveness=Intrusiveness.LIGHT, rule_name="r"
    )
    with pytest.raises(ToolError, match="Brak narzędzia"):
        SubprocessRunner().run("nmap", ["-sV"], target, timeout=1)
