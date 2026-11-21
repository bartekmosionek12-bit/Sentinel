"""Silnik powiadomień: deterministyczne reguły, deduplikacja i grupowanie per zasób."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.matching.engine import FindingChange
from app.models import Asset, Finding, Notification, Vulnerability
from app.models.base import utcnow
from app.models.finding import FINDING_TYPES
from app.notifications.channels import EXTERNAL_CHANNELS, ChannelError, Sender
from app.scoring.engine import LEVEL_ORDER

EVENTS = ("created", "reopened", "rescored")
DELIVERIES = ("immediate", "digest")
CHANNELS = ("in_app", *EXTERNAL_CHANNELS)


def _rank(level: str | None) -> int:
    """Im wyższa liczba, tym wyższy poziom ryzyka."""
    return len(LEVEL_ORDER) - LEVEL_ORDER.index(level) if level in LEVEL_ORDER else 0


@dataclass(frozen=True)
class NotificationRule:
    name: str
    description: str
    events: tuple[str, ...]
    delivery: str
    channels: tuple[str, ...]
    in_kev: bool | None = None
    exposure: str | None = None
    min_level: str | None = None
    finding_type: str | None = None

    def matches(self, change: FindingChange, asset: Asset, vuln: Vulnerability | None) -> bool:
        if change.kind not in self.events:
            return False
        if change.kind == "rescored" and _rank(change.after.get("level")) <= _rank(
            change.before.get("level")
        ):
            return False
        if self.in_kev is not None and bool(vuln and vuln.in_kev) != self.in_kev:
            return False
        if self.finding_type is not None and change.finding.type != self.finding_type:
            return False
        if self.exposure is not None and asset.exposure != self.exposure:
            return False
        return self.min_level is None or _rank(change.finding.risk_level) >= _rank(self.min_level)


@dataclass(frozen=True)
class NotificationConfig:
    rules: tuple[NotificationRule, ...]
    dedup_window_hours: int = 24

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NotificationConfig:
        rules: list[NotificationRule] = []
        for item in data.get("rules") or []:
            when = item.get("when") or {}
            rule = NotificationRule(
                name=str(item["name"]),
                description=str(item.get("description", "")),
                events=tuple(when.get("events") or EVENTS),
                delivery=str(item.get("delivery", "immediate")),
                channels=tuple(item.get("channels") or ("in_app",)),
                in_kev=when.get("in_kev"),
                exposure=when.get("exposure"),
                min_level=when.get("min_level"),
                finding_type=when.get("finding_type"),
            )
            if (
                set(rule.events) - set(EVENTS)
                or rule.delivery not in DELIVERIES
                or set(rule.channels) - set(CHANNELS)
                or (rule.min_level is not None and rule.min_level not in LEVEL_ORDER)
                or rule.exposure not in (None, "internet", "internal")
                or rule.finding_type not in (None, *FINDING_TYPES)
            ):
                raise ValueError(f"Nieprawidłowa reguła powiadomień: {rule.name}")
            rules.append(rule)
        if len({r.name for r in rules}) != len(rules):
            raise ValueError("Nazwy reguł powiadomień muszą być unikalne")
        return cls(tuple(rules), int(data.get("dedup_window_hours", 24)))

    @classmethod
    def from_file(cls, path: Path) -> NotificationConfig:
        return cls.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


class NoExternalChannels:
    """Domyślny nadawca: żaden kanał zewnętrzny nie jest włączony."""

    def configured(self) -> set[str]:
        return set()

    def send(self, channel: str, title: str, body: str) -> None:
        raise ChannelError(f"Kanał {channel} nie jest skonfigurowany")


@dataclass
class _Group:
    rule: NotificationRule
    asset: Asset
    items: list[tuple[Finding, Vulnerability | None]] = field(default_factory=list)


def _already_notified(session: Session, group_key: str, window_hours: int) -> set[str]:
    since = utcnow() - timedelta(hours=window_hours)
    seen: set[str] = set()
    payloads: Sequence[dict[str, Any]] = session.scalars(
        select(Notification.payload).where(
            Notification.group_key == group_key, Notification.created_at >= since
        )
    ).all()
    for payload in payloads:
        seen.update(payload.get("finding_ids", []))
    return seen


def notify(
    session: Session,
    changes: list[FindingChange],
    config: NotificationConfig,
    sender: Sender | None = None,
) -> list[Notification]:
    """Tworzy powiadomienia dla zmian findingów. Zwraca utworzone wiersze."""
    sender = sender or NoExternalChannels()
    groups: dict[str, _Group] = {}
    for change in changes:
        finding = change.finding
        asset = session.get(Asset, finding.asset_id)
        if asset is None:
            continue
        vuln = (
            session.get(Vulnerability, finding.vulnerability_id)
            if finding.vulnerability_id
            else None
        )
        rule = next((r for r in config.rules if r.matches(change, asset, vuln)), None)
        if rule is None:
            continue
        key = f"{rule.name}:{asset.id}"
        groups.setdefault(key, _Group(rule, asset)).items.append((finding, vuln))

    created: list[Notification] = []
    configured = sender.configured()
    for key, group in groups.items():
        seen = _already_notified(session, key, config.dedup_window_hours)
        fresh = [(f, v) for f, v in group.items if str(f.id) not in seen]
        if not fresh:
            continue
        fresh.sort(key=lambda item: -item[0].risk_score)
        rule, asset = group.rule, group.asset
        count = len(fresh)
        noun = "zagrożenie" if count == 1 else "zagrożenia" if count < 5 else "zagrożeń"
        title = f"{asset.name}: {count} {noun} ({rule.description})"
        lines = [
            f"{v.cve_id if v else f.type}: ryzyko {f.risk_score:.1f} ({f.risk_level}). "
            f"{f.risk_breakdown.get('summary', '')}"
            for f, v in fresh
        ]
        payload = {
            "title": title,
            "lines": lines,
            "asset_id": str(asset.id),
            "asset_name": asset.name,
            "delivery": rule.delivery,
            "finding_ids": [str(f.id) for f, _ in fresh],
            "cve_ids": [v.cve_id for _, v in fresh if v],
        }
        results: dict[str, str] = {}
        by_channel: dict[str, dict[str, Any]] = defaultdict(dict)
        for channel in rule.channels:
            if channel == "in_app":
                results[channel] = "sent" if rule.delivery == "immediate" else "digest_pending"
            elif channel not in configured:
                continue
            elif rule.delivery != "immediate":
                results[channel] = "digest_pending"
            else:
                try:
                    sender.send(channel, title, "\n".join(lines))
                    results[channel] = "sent"
                except ChannelError as error:
                    results[channel] = "failed"
                    by_channel[channel]["error"] = str(error)
        for channel, status in results.items():
            notification = Notification(
                finding_id=fresh[0][0].id,
                rule_name=rule.name,
                channel=channel,
                group_key=key,
                status=status,
                payload={**payload, **by_channel[channel]},
            )
            session.add(notification)
            created.append(notification)
        session.flush()
        audit.record(
            session,
            audit.AuditEvent(
                actor=f"rule:{rule.name}",
                action="notification_created",
                reason=rule.description,
                inputs={
                    "asset": asset.name,
                    "delivery": rule.delivery,
                    "channels": results,
                    "cve_ids": payload["cve_ids"],
                    "finding_ids": payload["finding_ids"],
                },
                object_type="asset",
                object_id=str(asset.id),
            ),
        )
    return created
