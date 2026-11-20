"""Audit log: tylko do dopisywania, z łańcuchem skrótów.

Każdy wpis odpowiada na pytania: co, kiedy, kto lub która reguła, dlaczego
i na podstawie jakich danych. Skrót wpisu obejmuje skrót poprzedniego, więc
usunięcie albo zmiana dowolnego wiersza jest wykrywalna przez `verify_chain`.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core import request_context
from app.models.base import utcnow
from app.models.ops import AuditLog

logger = logging.getLogger("sentinel.audit")

GENESIS_HASH = "0" * 64
_ADVISORY_LOCK_KEY = 0x53454E54  # "SENT"


@dataclass(frozen=True)
class AuditEvent:
    actor: str
    action: str
    reason: str
    inputs: dict[str, Any] = field(default_factory=dict)
    object_type: str | None = None
    object_id: str | None = None
    # Format 2 (Etap 4): kto dokładnie działał. `actor` zostaje czytelnym skrótem.
    actor_type: str | None = None  # human, agent, system, seed_demo
    actor_id: str | None = None  # identyfikator konta (sub z tokenu)
    on_behalf_of: str | None = None  # dla agenta: aktor, który zlecił zadanie
    request_id: str | None = None


HASH_VERSION = 2


class AuditSink(Protocol):
    def __call__(self, event: AuditEvent) -> None: ...


def _canonical_ts(ts: datetime) -> str:
    if ts.tzinfo is None:  # SQLite nie przechowuje strefy; zapisujemy zawsze UTC
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).isoformat(timespec="microseconds")


def _normalize(inputs: dict[str, Any]) -> dict[str, Any]:
    """Sprowadza dane do czystego JSON, żeby zapisane == policzone w skrócie."""
    normalized: dict[str, Any] = json.loads(json.dumps(inputs, default=str, ensure_ascii=False))
    return normalized


def compute_hash(
    prev_hash: str,
    ts: datetime,
    actor: str,
    action: str,
    object_type: str | None,
    object_id: str | None,
    reason: str,
    inputs: dict[str, Any],
    *,
    version: int = 1,
    actor_type: str | None = None,
    actor_id: str | None = None,
    on_behalf_of: str | None = None,
    request_id: str | None = None,
) -> str:
    payload: dict[str, Any] = {
        "prev": prev_hash,
        "ts": _canonical_ts(ts),
        "actor": actor,
        "action": action,
        "object_type": object_type,
        "object_id": object_id,
        "reason": reason,
        "inputs": inputs,
    }
    if version >= 2:
        payload |= {
            "v": version,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "on_behalf_of": on_behalf_of,
            "request_id": request_id,
        }
    body = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def record(session: Session, event: AuditEvent, *, now: datetime | None = None) -> AuditLog:
    """Dopisuje wpis do dziennika w bieżącej transakcji.

    Pola tożsamości, których zdarzenie nie podaje, pochodzą z kontekstu bieżącego żądania API.
    """
    context = request_context.current()
    if context is not None:
        event = replace(
            event,
            actor_type=event.actor_type or context.actor_type,
            actor_id=event.actor_id or context.actor_id,
            request_id=event.request_id or context.request_id,
        )
    if session.get_bind().dialect.name == "postgresql":
        # Serializuje dopisywanie, żeby dwa procesy nie użyły tego samego prev_hash.
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _ADVISORY_LOCK_KEY})
    prev_hash = session.scalar(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1))
    prev_hash = prev_hash or GENESIS_HASH
    ts = now or utcnow()
    inputs = _normalize(event.inputs)
    entry = AuditLog(
        ts=ts,
        actor=event.actor,
        action=event.action,
        object_type=event.object_type,
        object_id=event.object_id,
        reason=event.reason,
        inputs=inputs,
        actor_type=event.actor_type,
        actor_id=event.actor_id,
        on_behalf_of=event.on_behalf_of,
        request_id=event.request_id,
        hash_version=HASH_VERSION,
        prev_hash=prev_hash,
        hash=compute_hash(
            prev_hash,
            ts,
            event.actor,
            event.action,
            event.object_type,
            event.object_id,
            event.reason,
            inputs,
            version=HASH_VERSION,
            actor_type=event.actor_type,
            actor_id=event.actor_id,
            on_behalf_of=event.on_behalf_of,
            request_id=event.request_id,
        ),
    )
    session.add(entry)
    session.flush()
    logger.info(
        "audit",
        extra={
            "audit_id": entry.id,
            "actor": event.actor,
            "action": event.action,
            "object_type": event.object_type,
            "object_id": event.object_id,
            "reason": event.reason,
        },
    )
    return entry


@dataclass(frozen=True)
class ChainStatus:
    ok: bool
    entries: int
    broken_at_id: int | None = None
    detail: str | None = None


def verify_chain(session: Session) -> ChainStatus:
    """Przelicza cały łańcuch i wskazuje pierwszy niespójny wpis."""
    prev_hash = GENESIS_HASH
    count = 0
    for entry in session.scalars(select(AuditLog).order_by(AuditLog.id)).yield_per(1000):
        count += 1
        if entry.prev_hash != prev_hash:
            return ChainStatus(False, count, entry.id, "prev_hash nie zgadza się z poprzednim")
        expected = compute_hash(
            entry.prev_hash,
            entry.ts,
            entry.actor,
            entry.action,
            entry.object_type,
            entry.object_id,
            entry.reason,
            entry.inputs,
            version=entry.hash_version or 1,
            actor_type=entry.actor_type,
            actor_id=entry.actor_id,
            on_behalf_of=entry.on_behalf_of,
            request_id=entry.request_id,
        )
        if expected != entry.hash:
            return ChainStatus(False, count, entry.id, "treść wpisu została zmieniona")
        prev_hash = entry.hash
    return ChainStatus(True, count)


class DbAuditSink:
    """Zapisuje zdarzenia we własnej transakcji.

    Decyzja `scope_guard` (zwłaszcza odmowa) musi zostać w dzienniku także wtedy,
    gdy transakcja wywołującego zostanie wycofana.
    """

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def __call__(self, event: AuditEvent) -> None:
        with self._session_factory() as session:
            record(session, event)
            session.commit()
