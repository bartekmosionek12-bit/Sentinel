"""Audit log: łańcuch skrótów wykrywa każdą manipulację."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.audit import (
    GENESIS_HASH,
    AuditEvent,
    DbAuditSink,
    compute_hash,
    record,
    verify_chain,
)
from app.models import AuditLog


def _event(n: int) -> AuditEvent:
    return AuditEvent(
        actor="rule:new_host",
        action="scan_planned",
        reason=f"Powód numer {n}: zażółć gęślą jaźń",
        inputs={"n": n, "nested": {"b": 2, "a": [1, 2]}, "when": datetime(2026, 1, 1, tzinfo=UTC)},
        object_type="asset",
        object_id=str(n),
    )


def test_first_entry_links_to_genesis(session: Session) -> None:
    entry = record(session, _event(1))
    assert entry.prev_hash == GENESIS_HASH
    assert len(entry.hash) == 64


def test_chain_links_and_verifies(session: Session) -> None:
    entries = [record(session, _event(n)) for n in range(5)]
    session.commit()
    for previous, current in itertools.pairwise(entries):
        assert current.prev_hash == previous.hash
    status = verify_chain(session)
    assert status.ok
    assert status.entries == 5


def test_empty_chain_is_valid(session: Session) -> None:
    assert verify_chain(session).ok


def test_modified_entry_is_detected(session: Session) -> None:
    entries = [record(session, _event(n)) for n in range(4)]
    session.commit()
    session.execute(
        update(AuditLog).where(AuditLog.id == entries[1].id).values(reason="zmienione po fakcie")
    )
    session.commit()
    session.expire_all()
    status = verify_chain(session)
    assert not status.ok
    assert status.broken_at_id == entries[1].id


def test_modified_inputs_are_detected(session: Session) -> None:
    entry = record(session, _event(1))
    session.commit()
    session.execute(update(AuditLog).where(AuditLog.id == entry.id).values(inputs={"n": 999}))
    session.commit()
    session.expire_all()
    assert not verify_chain(session).ok


def test_deleted_entry_is_detected(session: Session) -> None:
    entries = [record(session, _event(n)) for n in range(4)]
    session.commit()
    session.delete(entries[1])
    session.commit()
    status = verify_chain(session)
    assert not status.ok
    assert status.broken_at_id == entries[2].id


def test_hash_is_deterministic_and_order_independent() -> None:
    ts = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    first = compute_hash(GENESIS_HASH, ts, "a", "b", None, None, "r", {"x": 1, "y": 2})
    second = compute_hash(GENESIS_HASH, ts, "a", "b", None, None, "r", {"y": 2, "x": 1})
    other = compute_hash(GENESIS_HASH, ts, "a", "b", None, None, "r", {"x": 1, "y": 3})
    assert first == second
    assert first != other


def test_db_sink_persists_in_own_transaction(session_factory: sessionmaker[Session]) -> None:
    sink = DbAuditSink(session_factory)
    sink(_event(1))
    sink(_event(2))
    with session_factory() as session:
        rows = session.scalars(select(AuditLog).order_by(AuditLog.id)).all()
        assert [r.object_id for r in rows] == ["1", "2"]
        assert verify_chain(session).ok
