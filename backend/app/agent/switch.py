"""Kill switch agenta: jeden wiersz w bazie, sprawdzany przed każdym wywołaniem narzędzia."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AgentSwitch


def is_killed(session: Session) -> bool:
    row = session.get(AgentSwitch, 1)
    return bool(row and row.killed)
