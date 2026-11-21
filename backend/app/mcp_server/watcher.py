"""Strażnik kill switcha w `mcp-scanner`: przerywa trwające wywołania agenta.

Flaga w bazie blokuje każde *nowe* wywołanie od razu (polityka w `ToolRuntime`). Wywołanie,
które już trwa (np. pełny skan portów), trzeba przerwać osobno: strażnik co sekundę czyta
flagę i przy przejściu w stan „wyłączony” zabija procesy narzędzi i zamyka połączenia SSH
zarejestrowane w `Cancellations`. Potwierdzenie (czas i liczba przerwanych wywołań) trafia do
`agent_switch` i do audytu, więc konsola pokazuje, że `mcp-scanner` naprawdę się zatrzymał.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session, sessionmaker

from app.core import audit
from app.models import AgentSwitch
from app.models.base import utcnow
from app.scanners.runner import CANCELLATIONS, Cancellations

logger = logging.getLogger("sentinel.mcp.watcher")


class KillWatcher:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        cancellations: Cancellations | None = None,
        *,
        interval: float = 1.0,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._sessions = sessions
        self._cancellations = cancellations or CANCELLATIONS
        self._interval = interval
        self._clock = clock
        self._seen: datetime | None = None
        self._stop = threading.Event()

    def tick(self) -> int | None:
        """Jedno sprawdzenie. Zwraca liczbę przerwanych wywołań, gdy obsłużył nowe wyłączenie."""
        with self._sessions() as session:
            switch = session.get(AgentSwitch, 1)
            if switch is None or not switch.killed or switch.killed_at is None:
                # Wywołania mogą trwać tylko przy włączonym agencie; nic do przerwania.
                return None
            if switch.scanner_stopped_at is not None or self._seen == switch.killed_at:
                # Ten kill switch już obsłużony; przerywamy też wywołania, które zdążyły
                # wystartować między sprawdzeniem polityki a zapisem flagi.
                self._cancellations.cancel_all()
                return None
            stopped = self._cancellations.cancel_all()
            self._seen = switch.killed_at
            switch.scanner_stopped_at = self._clock()
            switch.scanner_stopped = stopped
            audit.record(
                session,
                audit.AuditEvent(
                    actor="system:mcp-scanner",
                    action="agent_kill_scanner_stopped",
                    reason=f"mcp-scanner przerwał trwające wywołania agenta: {stopped}",
                    inputs={"stopped": stopped},
                    object_type="agent",
                    object_id="sentinel-agent",
                    actor_type="system",
                ),
            )
            session.commit()
            logger.warning("kill_switch_applied", extra={"stopped": stopped})
            return stopped

    def run_forever(self) -> None:  # pragma: no cover - pętla w kontenerze
        while not self._stop.wait(self._interval):
            try:
                self.tick()
            except Exception:
                logger.exception("kill_watcher_error")

    def start(self) -> threading.Thread:  # pragma: no cover - uruchamiane w kontenerze
        thread = threading.Thread(target=self.run_forever, name="kill-watcher", daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:  # pragma: no cover
        self._stop.set()
