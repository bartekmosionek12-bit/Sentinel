"""Własne sygnatury (R10, S1) i fingerprint HTTP: walidator, dopasowania, przekierowania."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from app.core.scope_guard import Intrusiveness, ScopeConfig, ScopeGuard
from app.discovery.engine import DiscoveryConfig
from app.discovery.fingerprint import HttpFingerprinter, _same_origin, flags_for, web_ports
from app.discovery.signatures import (
    MAX_PATHS,
    Observed,
    SignatureError,
    evaluate,
    load_signatures,
    parse_signatures,
)
from tests.conftest import FakeResolver, MemoryAudit

RULES = Path(__file__).resolve().parents[2] / "rules"


def _sig(**match: object) -> dict[str, object]:
    return {"signatures": [{"id": "x1", "name": "X", "kind": "technology", "match": [match]}]}


def _seen(**kw: object) -> Observed:
    base: dict[str, object] = {
        "headers": {},
        "cookies": [],
        "body": "",
        "title": "",
        "generator": "",
        "favicon_hash": None,
        "paths": {},
        "path_bodies": {},
    }
    return Observed(**{**base, **kw})  # type: ignore[arg-type]


def test_repo_signatures_load_and_respect_path_limit() -> None:
    signatures = load_signatures(RULES / "signatures.yaml")
    assert {s.id for s in signatures} >= {"gitea", "rabbitmq-management", "adminer", "traefik"}
    paths = {m.path for s in signatures for m in s.matches if m.type == "path"}
    assert len(paths) <= MAX_PATHS
    assert DiscoveryConfig.from_file(RULES / "discovery.yaml").signatures == signatures


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (_sig(type="path", path="/login", method="POST"), "niedozwolone pola"),
        (_sig(type="path", path="/login?user=admin&password=x"), "niedozwolona"),
        (_sig(type="path", path="/../etc/passwd"), "niedozwolona"),
        (_sig(type="path", path="http://evil.example/"), "niedozwolona"),
        (_sig(type="html", pattern="x", body="payload"), "niedozwolone pola"),
        (_sig(type="exec", pattern="x"), "spoza"),
        (_sig(type="title", pattern="("), "błędny wzorzec"),
        (
            {
                "signatures": [
                    {"id": "a1", "kind": "exploit", "match": [{"type": "title", "pattern": "x"}]}
                ]
            },
            "rodzaj",
        ),
        (
            {
                "signatures": [
                    {"id": "a1", "kind": "panel", "credentials": "admin:admin", "match": []}
                ]
            },
            "niedozwolone pola",
        ),
    ],
)
def test_validator_rejects_unsafe_or_broken_signatures(raw: object, message: str) -> None:
    with pytest.raises(SignatureError, match=message):
        parse_signatures(raw)


def test_validator_limits_number_of_extra_requests() -> None:
    raw = {
        "signatures": [
            {"id": f"p{i:02d}", "kind": "panel", "match": [{"type": "path", "path": f"/p{i}"}]}
            for i in range(MAX_PATHS + 1)
        ]
    }
    with pytest.raises(SignatureError, match="limit"):
        parse_signatures(raw)


def test_all_brief_match_types_work() -> None:
    signatures = parse_signatures(
        {
            "signatures": [
                {
                    "id": "h1",
                    "kind": "technology",
                    "match": [{"type": "header", "name": "x-gitea", "pattern": "1\\."}],
                },
                {
                    "id": "c1",
                    "kind": "technology",
                    "match": [{"type": "cookie", "pattern": "^i_like_gitea$"}],
                },
                {
                    "id": "f1",
                    "kind": "technology",
                    "match": [{"type": "favicon_hash", "value": -1}],
                },
                {
                    "id": "b1",
                    "kind": "technology",
                    "match": [{"type": "html", "pattern": "powered by gitea"}],
                },
                {"id": "t1", "kind": "panel", "match": [{"type": "title", "pattern": "sign in"}]},
                {
                    "id": "g1",
                    "kind": "technology",
                    "match": [{"type": "generator", "pattern": "wordpress 4\\.7"}],
                },
                {
                    "id": "p1",
                    "kind": "panel",
                    "match": [{"type": "path", "path": "/version", "status": [200]}],
                },
            ]
        }
    )
    hits = evaluate(
        signatures,
        _seen(
            headers={"x-gitea": "1.22"},
            cookies=["i_like_gitea"],
            body="<footer>Powered by Gitea</footer>",
            title="Sign In",
            generator="WordPress 4.7",
            favicon_hash=-1,
            paths={"/version": 200},
        ),
    )
    assert [h["id"] for h in hits] == ["h1", "c1", "f1", "b1", "t1", "g1", "p1"]
    assert evaluate(signatures, _seen(paths={"/version": 404})) == []


def test_path_pattern_rejects_single_page_app_catch_all() -> None:
    """Nginx Proxy Manager (SPA) zwraca 200 na /wp-login.php: sam kod to za mało."""
    signatures = load_signatures(RULES / "signatures.yaml")
    spa = _seen(paths={"/wp-login.php": 200}, path_bodies={"/wp-login.php": "<div id=app>"})
    assert "wordpress-login" not in [h["id"] for h in evaluate(signatures, spa)]
    wp = _seen(
        paths={"/wp-login.php": 200},
        path_bodies={"/wp-login.php": '<input name="log" id="user_login">'},
    )
    assert "wordpress-login" in [h["id"] for h in evaluate(signatures, wp)]


def test_same_origin_ignores_default_port_in_url() -> None:
    assert _same_origin("http://10.0.0.5/login.php", "http", "10.0.0.5", 80)
    assert _same_origin("https://10.0.0.5/x", "https", "10.0.0.5", 443)
    assert _same_origin("http://10.0.0.5:8088/wp-admin/", "http", "10.0.0.5", 8088)
    assert not _same_origin("http://10.0.0.6/", "http", "10.0.0.5", 80)
    assert not _same_origin("https://10.0.0.5/", "http", "10.0.0.5", 80)
    assert not _same_origin("http://10.0.0.5:81/", "http", "10.0.0.5", 80)


def test_unusual_web_ports_get_fingerprinted() -> None:
    services = [
        {"port": 3001, "name": "nessus"},
        {"port": 15672, "name": "unknown"},
        {"port": 5672, "name": "amqp"},
    ]
    assert web_ports(services) == [(3001, "http"), (15672, "http")]


def test_fingerprint_follows_redirect_on_port_80_and_applies_signatures() -> None:
    """Przypadek z labu organizatorów: DVWA na :80 przekierowuje na /login.php."""
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        path = request.url.path
        if path == "/":
            return httpx.Response(302, headers={"location": "login.php"})
        if path == "/login.php":
            html = "<title>Login :: Damn Vulnerable Web Application (DVWA)</title>"
            return httpx.Response(200, text=html, headers={"set-cookie": "PHPSESSID=1; path=/"})
        if path == "/wp-login.php":
            return httpx.Response(404)
        return httpx.Response(404)

    guard = ScopeGuard(
        ScopeConfig.from_dict({"allow": {"cidrs": ["10.0.0.0/24"]}}),
        audit=MemoryAudit(),
        resolver=FakeResolver(),
    )
    target = guard.authorize(
        "10.0.0.5", tool="http_probe", intrusiveness=Intrusiveness.LIGHT, rule_name="test"
    )
    signatures = load_signatures(RULES / "signatures.yaml")
    prober = HttpFingerprinter(["/admin", "/login"], signatures=signatures)
    prober._client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    result = prober.probe(target, 80, "http")
    assert result.status == 200
    assert "DVWA" in result.title
    assert "DVWA" in result.technologies
    assert result.redirects == ["http://10.0.0.5/login.php"]
    assert set(methods) == {"GET"}
    assert "/wp-login.php" in result.paths  # ścieżka z sygnatury: jedno GET
    flags = {f["kind"]: f for f in flags_for(None, [result.as_dict()])}
    assert "panel" in flags


def test_signature_hits_become_flag_evidence() -> None:
    item = {
        "port": 15672,
        "scheme": "http",
        "title": "RabbitMQ Management",
        "signatures": [
            {
                "id": "rabbitmq-management",
                "name": "Panel RabbitMQ Management",
                "kind": "panel",
                "evidence": ["tytuł"],
            }
        ],
    }
    (panel,) = [f for f in flags_for(None, [item]) if f["kind"] == "panel"]
    assert any("RabbitMQ" in e for e in panel["evidence"])
