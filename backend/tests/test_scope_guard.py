"""scope_guard: allowlista, denylista, DNS, zgody L2, limity i audit każdej decyzji."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import pytest

from app.core.scope_guard import (
    ApprovalRequired,
    HumanApproval,
    InMemoryRateLimiter,
    Intrusiveness,
    RateLimited,
    ScopeConfig,
    ScopeDenied,
    ScopedTarget,
    ScopeGuard,
    SeedDemoApproval,
    domain_matches,
    require_scoped,
)
from tests.conftest import FakeResolver, MemoryAudit

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
LAB = ip_network("172.30.99.0/24")

BASE_SCOPE = {
    "allow": {
        "domains": ["shop.example.lab", "*.corp.example.lab"],
        "cidrs": ["10.10.0.0/24", "172.30.99.0/24", "fd00:99::/64"],
    },
    "deny": {"domains": ["hr.corp.example.lab"], "cidrs": ["10.10.0.128/25"]},
}


def make_guard(
    audit: MemoryAudit,
    scope: Mapping[str, Any] | None = None,
    dns: dict[str, list[str]] | None = None,
    seed_demo: SeedDemoApproval | None = None,
    limiter: InMemoryRateLimiter | None = None,
) -> ScopeGuard:
    return ScopeGuard(
        ScopeConfig.from_dict(dict(BASE_SCOPE if scope is None else scope)),
        audit=audit,
        resolver=FakeResolver(dns),
        rate_limiter=limiter,
        seed_demo=seed_demo,
        clock=lambda: NOW,
    )


def authorize(
    guard: ScopeGuard,
    target: str,
    level: Intrusiveness = Intrusiveness.LIGHT,
    approval: HumanApproval | None = None,
) -> ScopedTarget:
    return guard.authorize(
        target, tool="nmap", intrusiveness=level, rule_name="test_rule", approval=approval
    )


# --- zakres domyślny i CIDR ---------------------------------------------------


def test_empty_config_denies_everything(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink, scope={})
    for target in ("10.10.0.5", "127.0.0.1", "8.8.8.8", "example.com", "::1"):
        with pytest.raises(ScopeDenied):
            authorize(guard, target)
    assert audit_sink.actions == ["scope_denied"] * 5


def test_missing_scope_file_means_empty_scope(tmp_path: Path) -> None:
    config = ScopeConfig.from_file(tmp_path / "nie-ma.yaml")
    assert config.allowed_cidrs == ()
    assert config.allowed_domains == ()


def test_shipped_scope_file_is_empty_by_default() -> None:
    shipped = Path(__file__).resolve().parents[2] / "rules" / "scope.yaml"
    config = ScopeConfig.from_file(shipped)
    assert config.allowed_cidrs == ()
    assert config.allowed_domains == ()


@pytest.mark.parametrize("target", ["10.10.0.0", "10.10.0.1", "10.10.0.127", "fd00:99::10"])
def test_ip_inside_allowed_cidr(audit_sink: MemoryAudit, target: str) -> None:
    scoped = authorize(make_guard(audit_sink), target)
    assert scoped.ip == ip_address(target)
    assert scoped.address == str(ip_address(target))
    assert audit_sink.actions == ["scope_allowed"]


@pytest.mark.parametrize(
    "target",
    ["10.10.1.0", "10.9.255.255", "8.8.8.8", "127.0.0.1", "169.254.169.254", "fd00:98::1", "::1"],
)
def test_ip_outside_allowed_cidr(audit_sink: MemoryAudit, target: str) -> None:
    with pytest.raises(ScopeDenied):
        authorize(make_guard(audit_sink), target)
    assert audit_sink.actions == ["scope_denied"]


@pytest.mark.parametrize("target", ["10.10.0.128", "10.10.0.200", "10.10.0.255"])
def test_denylist_wins_over_allowlist(audit_sink: MemoryAudit, target: str) -> None:
    with pytest.raises(ScopeDenied, match="denyliście"):
        authorize(make_guard(audit_sink), target)


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "http://10.10.0.5",
        "10.10.0.5:80",
        "10.10.0.0/24",
        "10.10.0.5/32",
        "10.10.0.5 ; rm -rf /",
        "-oN/tmp/x",
        "shop.example.lab/path",
        "a b",
    ],
)
def test_malformed_targets_are_denied(audit_sink: MemoryAudit, target: str) -> None:
    with pytest.raises(ScopeDenied):
        authorize(make_guard(audit_sink), target)


# --- domeny i DNS ---------------------------------------------------------------


def test_domain_matching_rules() -> None:
    assert domain_matches("shop.example.lab", "shop.example.lab")
    assert not domain_matches("x.shop.example.lab", "shop.example.lab")
    assert domain_matches("a.corp.example.lab", "*.corp.example.lab")
    assert domain_matches("a.b.corp.example.lab", "*.corp.example.lab")
    assert not domain_matches("corp.example.lab", "*.corp.example.lab")
    assert not domain_matches("evilcorp.example.lab", "*.corp.example.lab")
    assert not domain_matches("corp.example.lab.evil.com", "*.corp.example.lab")


def test_allowed_domain_resolving_in_scope(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink, dns={"shop.example.lab": ["10.10.0.7"]})
    scoped = authorize(guard, "Shop.Example.LAB.")
    assert scoped.hostname == "shop.example.lab"
    assert scoped.address == "10.10.0.7"  # narzędzie dostaje IP, nie nazwę


def test_domain_not_on_allowlist_is_denied_without_dns_lookup(audit_sink: MemoryAudit) -> None:
    resolver = FakeResolver({"other.example.lab": ["10.10.0.7"]})
    guard = ScopeGuard(ScopeConfig.from_dict(BASE_SCOPE), audit=audit_sink, resolver=resolver)
    with pytest.raises(ScopeDenied, match="allowlistą"):
        authorize(guard, "other.example.lab")
    assert resolver.calls == []


def test_allowed_domain_resolving_out_of_scope_is_denied(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink, dns={"shop.example.lab": ["93.184.216.34"]})
    with pytest.raises(ScopeDenied, match="poza dozwolonymi"):
        authorize(guard, "shop.example.lab")


def test_domain_with_any_address_out_of_scope_is_denied(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink, dns={"shop.example.lab": ["10.10.0.7", "127.0.0.1"]})
    with pytest.raises(ScopeDenied):
        authorize(guard, "shop.example.lab")


def test_denied_domain_wins_over_wildcard_allow(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink, dns={"hr.corp.example.lab": ["10.10.0.9"]})
    with pytest.raises(ScopeDenied, match="denyliście"):
        authorize(guard, "hr.corp.example.lab")


def test_unresolvable_domain_is_denied(audit_sink: MemoryAudit) -> None:
    with pytest.raises(ScopeDenied, match="nie rozwiązuje"):
        authorize(make_guard(audit_sink), "shop.example.lab")


def test_invalid_scope_patterns_are_rejected() -> None:
    for bad in ("*", "*.*.example.lab", "exa*mple.lab", "http://example.lab"):
        with pytest.raises(ValueError, match="domeny"):
            ScopeConfig.from_dict({"allow": {"domains": [bad]}})
    with pytest.raises(ValueError, match="host bits"):
        ScopeConfig.from_dict({"allow": {"cidrs": ["10.10.0.1/24"]}})


# --- poziomy inwazyjności i zgoda człowieka -----------------------------------------


def test_forbidden_level_is_always_denied(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink)
    with pytest.raises(ScopeDenied, match="zabroniony"):
        authorize(guard, "10.10.0.5", Intrusiveness.FORBIDDEN, HumanApproval("admin", "test"))


def test_intrusive_requires_human_approval(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink)
    with pytest.raises(ApprovalRequired):
        authorize(guard, "10.10.0.5", Intrusiveness.INTRUSIVE)
    assert audit_sink.actions == ["scope_awaiting_approval"]


def test_intrusive_with_human_approval(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink)
    scoped = authorize(
        guard, "10.10.0.5", Intrusiveness.INTRUSIVE, HumanApproval("anna", "okno serwisowe")
    )
    assert scoped.approval_source == "human:anna"
    assert audit_sink.events[-1].inputs["approval_reason"] == "okno serwisowe"


def test_blank_human_approval_is_not_an_approval(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink)
    with pytest.raises(ApprovalRequired):
        authorize(guard, "10.10.0.5", Intrusiveness.INTRUSIVE, HumanApproval(" ", "powód"))
    with pytest.raises(ApprovalRequired):
        authorize(guard, "10.10.0.5", Intrusiveness.INTRUSIVE, HumanApproval("anna", ""))


def test_human_approval_does_not_bypass_scope(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink)
    with pytest.raises(ScopeDenied):
        authorize(guard, "8.8.8.8", Intrusiveness.INTRUSIVE, HumanApproval("anna", "bo tak"))


# --- zgoda seed_demo (warunki zaakceptowane 2026-11-16) ---------------------------


def seed(
    demo_mode: bool = True, expires: datetime | None = NOW + timedelta(hours=6)
) -> SeedDemoApproval:
    return SeedDemoApproval(demo_mode=demo_mode, lab_network=LAB, expires_at=expires)


def test_seed_demo_approval_works_inside_lab(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink, seed_demo=seed())
    scoped = authorize(guard, "172.30.99.10", Intrusiveness.INTRUSIVE)
    assert scoped.approval_source == "seed_demo"
    event = audit_sink.events[-1]
    assert event.action == "scope_allowed"
    assert event.inputs["approval_source"] == "seed_demo"
    assert event.inputs["approval_expires_at"] == NOW + timedelta(hours=6)


@pytest.mark.parametrize(
    "target",
    [
        "10.10.0.5",  # na allowliście użytkownika, ale poza siecią demo-lab
        "fd00:99::10",  # na allowliście, inna rodzina adresów
        "172.30.98.255",  # tuż przed siecią laboratorium
        "172.30.100.0",  # tuż za siecią laboratorium
    ],
)
def test_seed_demo_approval_never_covers_addresses_outside_lab(
    audit_sink: MemoryAudit, target: str
) -> None:
    scope = {"allow": {"cidrs": ["10.10.0.0/24", "172.30.0.0/16", "fd00:99::/64"]}}
    guard = make_guard(audit_sink, scope=scope, seed_demo=seed())
    with pytest.raises(ApprovalRequired):
        authorize(guard, target, Intrusiveness.INTRUSIVE)


def test_seed_demo_approval_disabled_without_demo_mode(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink, seed_demo=seed(demo_mode=False))
    with pytest.raises(ApprovalRequired):
        authorize(guard, "172.30.99.10", Intrusiveness.INTRUSIVE)


def test_seed_demo_approval_expires(audit_sink: MemoryAudit) -> None:
    for expires in (NOW, NOW - timedelta(seconds=1), None):
        guard = make_guard(audit_sink, seed_demo=seed(expires=expires))
        with pytest.raises(ApprovalRequired):
            authorize(guard, "172.30.99.10", Intrusiveness.INTRUSIVE)


def test_seed_demo_approval_does_not_bypass_scope(audit_sink: MemoryAudit) -> None:
    """Adres w sieci demo-lab, ale spoza allowlisty: brama nadal odmawia."""
    guard = make_guard(audit_sink, scope={"allow": {"cidrs": ["10.10.0.0/24"]}}, seed_demo=seed())
    with pytest.raises(ScopeDenied):
        authorize(guard, "172.30.99.10", Intrusiveness.INTRUSIVE)


def test_seed_demo_approval_does_not_bypass_denylist(audit_sink: MemoryAudit) -> None:
    scope = {"allow": {"cidrs": ["172.30.99.0/24"]}, "deny": {"cidrs": ["172.30.99.10/32"]}}
    guard = make_guard(audit_sink, scope=scope, seed_demo=seed())
    with pytest.raises(ScopeDenied):
        authorize(guard, "172.30.99.10", Intrusiveness.INTRUSIVE)


def test_seed_demo_approval_requires_every_resolved_address_in_lab(
    audit_sink: MemoryAudit,
) -> None:
    scope = {"allow": {"domains": ["mix.lab"], "cidrs": ["172.30.99.0/24", "10.10.0.0/24"]}}
    guard = make_guard(
        audit_sink, scope=scope, dns={"mix.lab": ["172.30.99.10", "10.10.0.5"]}, seed_demo=seed()
    )
    with pytest.raises(ApprovalRequired):
        authorize(guard, "mix.lab", Intrusiveness.INTRUSIVE)


def test_seed_demo_covers_unit() -> None:
    lab_ip, other_ip = ip_address("172.30.99.10"), ip_address("10.10.0.5")
    assert seed().covers([lab_ip], NOW)
    assert not seed().covers([], NOW)
    assert not seed().covers([lab_ip, other_ip], NOW)
    assert not seed(demo_mode=False).covers([lab_ip], NOW)
    assert not seed(expires=None).covers([lab_ip], NOW)
    assert not seed().covers([lab_ip], NOW + timedelta(hours=6))


# --- limity szybkości ---------------------------------------------------------------


def test_rate_limit_per_target(audit_sink: MemoryAudit) -> None:
    now = [0.0]
    limiter = InMemoryRateLimiter(clock=lambda: now[0])
    scope = {"allow": {"cidrs": ["10.10.0.0/24"]}, "rate_limits": {"default_per_minute": 2}}
    guard = make_guard(audit_sink, scope=scope, limiter=limiter)
    authorize(guard, "10.10.0.5")
    authorize(guard, "10.10.0.5")
    with pytest.raises(RateLimited):
        authorize(guard, "10.10.0.5")
    authorize(guard, "10.10.0.6")  # inny cel ma własny limit
    now[0] = 61.0
    authorize(guard, "10.10.0.5")
    assert audit_sink.actions.count("scope_rate_limited") == 1


def test_rate_limit_override_per_target(audit_sink: MemoryAudit) -> None:
    scope = {
        "allow": {"cidrs": ["10.10.0.0/24"]},
        "rate_limits": {"default_per_minute": 10, "per_target": {"10.10.0.5": 1}},
    }
    guard = make_guard(audit_sink, scope=scope)
    authorize(guard, "10.10.0.5")
    with pytest.raises(RateLimited):
        authorize(guard, "10.10.0.5")


def test_dry_run_does_not_consume_rate_limit(audit_sink: MemoryAudit) -> None:
    scope = {"allow": {"cidrs": ["10.10.0.0/24"]}, "rate_limits": {"default_per_minute": 1}}
    guard = make_guard(audit_sink, scope=scope)
    for _ in range(5):
        guard.authorize(
            "10.10.0.5",
            tool="scope_check",
            intrusiveness=Intrusiveness.LIGHT,
            rule_name="manual",
            dry_run=True,
        )
    authorize(guard, "10.10.0.5")


# --- kontrakt ScopedTarget -------------------------------------------------------------


def test_scoped_target_cannot_be_forged() -> None:
    with pytest.raises(TypeError, match="wyłącznie ScopeGuard"):
        ScopedTarget(
            original="8.8.8.8",
            ip=ip_address("8.8.8.8"),
            hostname=None,
            tool="nmap",
            intrusiveness=Intrusiveness.LIGHT,
            rule_name="forged",
        )
    with pytest.raises(TypeError):
        ScopedTarget(
            original="8.8.8.8",
            ip=ip_address("8.8.8.8"),
            hostname=None,
            tool="nmap",
            intrusiveness=Intrusiveness.LIGHT,
            rule_name="forged",
            _seal=object(),
        )


def test_require_scoped_rejects_plain_values(audit_sink: MemoryAudit) -> None:
    for value in ("10.10.0.5", ip_address("10.10.0.5"), None, {"ip": "10.10.0.5"}):
        with pytest.raises(TypeError, match="ScopedTarget"):
            require_scoped(value)
    scoped = authorize(make_guard(audit_sink), "10.10.0.5")
    assert require_scoped(scoped) is scoped


def test_every_decision_is_audited_with_rule_name(audit_sink: MemoryAudit) -> None:
    guard = make_guard(audit_sink)
    authorize(guard, "10.10.0.5")
    with pytest.raises(ScopeDenied):
        authorize(guard, "8.8.8.8")
    assert [e.action for e in audit_sink.events] == ["scope_allowed", "scope_denied"]
    for event in audit_sink.events:
        assert event.actor == "rule:test_rule"
        assert event.inputs["tool"] == "nmap"
        assert event.reason
