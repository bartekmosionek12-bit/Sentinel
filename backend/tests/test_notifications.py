"""Powiadomienia: reguły, pierwszeństwo, grupowanie, deduplikacja i kanały."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.matching.engine import build_normalizer, evaluate_findings, resolve_products
from app.models import AuditLog, Vulnerability
from app.notifications.channels import ChannelError, ChannelSender
from app.notifications.engine import NotificationConfig, notify
from tests.pipeline_helpers import (
    ALIASES,
    MATCHING,
    RULES,
    SCORING,
    asset_by_ip,
    seed_feeds,
    seed_inventory,
)

CONFIG = NotificationConfig.from_file(RULES / "notifications.yaml")


class RecordingSender:
    def __init__(self, channels: set[str], fail: bool = False) -> None:
        self._channels = channels
        self._fail = fail
        self.sent: list[tuple[str, str, str]] = []

    def configured(self) -> set[str]:
        return self._channels

    def send(self, channel: str, title: str, body: str) -> None:
        if self._fail:
            raise ChannelError("odpowiedź HTTP 500")
        self.sent.append((channel, title, body))


@pytest.fixture
def seeded(session: Session) -> Session:
    seed_feeds(session)
    seed_inventory(session)
    resolve_products(session, build_normalizer(session, ALIASES), MATCHING)
    return session


def test_kev_on_internet_asset_gives_one_grouped_immediate_notification(seeded: Session) -> None:
    report = evaluate_findings(seeded, SCORING)
    created = notify(seeded, report.changes, CONFIG)
    # web-01: dwa CVE z KEV w jednym powiadomieniu; proxy-01 ma niskie ryzyko, więc cisza
    (notification,) = created
    assert (notification.rule_name, notification.channel, notification.status) == (
        "kev_na_zasobie_z_internetu",
        "in_app",
        "sent",
    )
    assert notification.payload["cve_ids"] == ["CVE-2021-42013", "CVE-2021-41773"]
    assert notification.payload["title"].startswith("web-01: 2 zagrożenia")
    assert "172.30.99.10" not in str(notification.payload)
    assert "notification_created" in seeded.scalars(select(AuditLog.action)).all()


def test_same_findings_are_not_notified_twice(seeded: Session) -> None:
    report = evaluate_findings(seeded, SCORING)
    assert len(notify(seeded, report.changes, CONFIG)) == 1
    assert notify(seeded, report.changes, CONFIG) == []


def test_first_matching_rule_wins_and_high_risk_waits_for_digest(seeded: Session) -> None:
    web = asset_by_ip(seeded, "172.30.99.10")
    web.exposure = "internal"
    web.criticality = 3
    proxy = asset_by_ip(seeded, "172.30.99.11")
    proxy.exposure = "internet"
    proxy.criticality = 5
    seeded.flush()
    report = evaluate_findings(seeded, SCORING)
    by_rule = {n.rule_name: n for n in notify(seeded, report.changes, CONFIG)}
    # web-01 wewnętrzny: 42013 nadal krytyczny (80.3), 41773 wysoki (73.4, digest)
    assert by_rule["ryzyko_krytyczne"].payload["cve_ids"] == ["CVE-2021-42013"]
    assert by_rule["ryzyko_wysokie"].payload["cve_ids"] == ["CVE-2021-41773"]
    assert by_rule["ryzyko_wysokie"].status == "digest_pending"
    assert "kev_na_zasobie_z_internetu" not in by_rule


def test_rescore_notifies_only_when_level_rises(seeded: Session) -> None:
    proxy = asset_by_ip(seeded, "172.30.99.11")
    proxy.exposure = "internet"
    seeded.flush()
    notify(seeded, evaluate_findings(seeded, SCORING).changes, CONFIG)
    vuln = seeded.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2021-23017"))
    assert vuln is not None

    vuln.epss = 0.33  # ocena rośnie, poziom zostaje
    seeded.flush()
    report = evaluate_findings(seeded, SCORING)
    assert len(report.of_kind("rescored")) == 1
    assert notify(seeded, report.changes, CONFIG) == []

    vuln.in_kev = True  # scenariusz „zero-day”: CVE trafia do KEV
    seeded.flush()
    report = evaluate_findings(seeded, SCORING)
    (notification,) = notify(seeded, report.changes, CONFIG)
    assert notification.rule_name == "kev_na_zasobie_z_internetu"
    assert notification.payload["asset_name"] == "proxy-01"


def test_external_channels_only_when_configured_and_failures_are_recorded(
    seeded: Session,
) -> None:
    report = evaluate_findings(seeded, SCORING)
    sender = RecordingSender({"slack"})
    created = notify(seeded, report.changes, CONFIG, sender)
    assert {(n.channel, n.status) for n in created} == {("in_app", "sent"), ("slack", "sent")}
    assert [channel for channel, _, _ in sender.sent] == ["slack"]


def test_failed_channel_is_recorded_not_raised(seeded: Session) -> None:
    report = evaluate_findings(seeded, SCORING)
    created = notify(seeded, report.changes, CONFIG, RecordingSender({"teams"}, fail=True))
    failed = next(n for n in created if n.channel == "teams")
    assert failed.status == "failed"
    assert "HTTP 500" in failed.payload["error"]


@pytest.mark.parametrize(
    "rule",
    [
        {"name": "x", "when": {"events": ["deleted"]}},
        {"name": "x", "delivery": "later"},
        {"name": "x", "channels": ["pager"]},
        {"name": "x", "when": {"min_level": "ogromny"}},
        {"name": "x", "when": {"exposure": "dmz"}},
    ],
)
def test_invalid_rules_are_rejected(rule: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="Nieprawidłowa reguła"):
        NotificationConfig.from_dict({"rules": [rule]})


def test_duplicate_rule_names_are_rejected() -> None:
    with pytest.raises(ValueError, match="unikalne"):
        NotificationConfig.from_dict({"rules": [{"name": "a"}, {"name": "a"}]})


def _settings(**values: Any) -> Settings:
    return Settings(_env_file=None, **values)


def test_no_channel_is_configured_by_default() -> None:
    sender = ChannelSender(_settings())
    assert sender.configured() == set()
    with pytest.raises(ChannelError, match="nie jest skonfigurowany"):
        sender.send("slack", "t", "b")


def test_webhook_posts_only_to_provider_hosts() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    good = ChannelSender(
        _settings(SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/x"), client=client
    )
    good.send("slack", "tytuł", "treść")
    assert requests[0].url.host == "hooks.slack.com"
    assert b"tytu" in requests[0].content

    for url in ("https://evil.example/hook", "http://hooks.slack.com/services/x"):
        bad = ChannelSender(_settings(SLACK_WEBHOOK_URL=url), client=client)
        with pytest.raises(ChannelError, match="hostów dostawcy"):
            bad.send("slack", "t", "b")
    teams = ChannelSender(
        _settings(TEAMS_WEBHOOK_URL="https://contoso.webhook.office.com/webhookb2/x"),
        client=client,
    )
    teams.send("teams", "t", "b")
    assert len(requests) == 2


def test_webhook_http_error_becomes_channel_error() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(500)))
    sender = ChannelSender(
        _settings(SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T/B/x"), client=client
    )
    with pytest.raises(ChannelError, match="HTTP 500"):
        sender.send("slack", "t", "b")


def test_email_uses_starttls_and_configured_addresses() -> None:
    calls: list[Any] = []

    class FakeSmtp:
        def __init__(self, host: str, port: int) -> None:
            calls.append(("connect", host, port))

        def __enter__(self) -> FakeSmtp:
            return self

        def __exit__(self, *_: object) -> None:
            calls.append(("quit",))

        def starttls(self) -> None:
            calls.append(("starttls",))

        def login(self, user: str, password: str) -> None:
            calls.append(("login", user))

        def send_message(self, message: Any) -> None:
            calls.append(("send", message["To"], message["Subject"]))

    sender = ChannelSender(
        _settings(
            SMTP_HOST="mail.demo.lab",
            SMTP_FROM="sentinel@demo.lab",
            SMTP_USER="sentinel",
            SMTP_PASSWORD="x",
            NOTIFY_EMAIL_TO="soc@demo.lab",
        ),
        smtp_factory=FakeSmtp,  # type: ignore[arg-type]
    )
    assert sender.configured() == {"email"}
    sender.send("email", "web-01: 1 zagrożenie", "treść")
    assert calls == [
        ("connect", "mail.demo.lab", 587),
        ("starttls",),
        ("login", "sentinel"),
        ("send", "soc@demo.lab", "[Sentinel ASI] web-01: 1 zagrożenie"),
        ("quit",),
    ]
