"""Strumień zdarzeń generowania: worker `llm` publikuje, API przekazuje dalej przez SSE.

API nie rozmawia z modelem, więc limit jednego zadania inferencji naraz zawsze
obowiązuje. Zdarzenia leżą w strumieniu Redisa, dzięki czemu klient, który podłączy się
chwilę po starcie, dostaje je od początku.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from typing import Any, Protocol

TERMINAL = frozenset({"done", "error"})
STREAM_TTL_SECONDS = 900
STREAM_MAX_LEN = 4000
START_ID = "0-0"


def stream_key(job_id: str) -> str:
    return f"llm:job:{job_id}"


class EventBus(Protocol):
    def publish(self, job_id: str, event: dict[str, Any]) -> None: ...

    def read(
        self, job_id: str, last_id: str, *, block_ms: int
    ) -> list[tuple[str, dict[str, Any]]]: ...


class RedisEventBus:
    def __init__(self, redis_url: str) -> None:
        import redis

        self._redis = redis.Redis.from_url(redis_url, decode_responses=True)

    def publish(self, job_id: str, event: dict[str, Any]) -> None:
        key = stream_key(job_id)
        self._redis.xadd(key, {"e": json.dumps(event, ensure_ascii=False)}, maxlen=STREAM_MAX_LEN)
        self._redis.expire(key, STREAM_TTL_SECONDS)

    def read(self, job_id: str, last_id: str, *, block_ms: int) -> list[tuple[str, dict[str, Any]]]:
        result: Any = self._redis.xread({stream_key(job_id): last_id}, block=block_ms, count=200)
        events: list[tuple[str, dict[str, Any]]] = []
        for _key, entries in result or []:
            for entry_id, fields in entries:
                events.append((str(entry_id), json.loads(fields["e"])))
        return events


class MemoryEventBus:
    """Do testów: ta sama semantyka co strumień Redisa, w pamięci procesu."""

    def __init__(self) -> None:
        self._events: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._condition = threading.Condition()

    def publish(self, job_id: str, event: dict[str, Any]) -> None:
        with self._condition:
            self._events[job_id].append(event)
            self._condition.notify_all()

    def read(self, job_id: str, last_id: str, *, block_ms: int) -> list[tuple[str, dict[str, Any]]]:
        start = int(last_id.split("-")[0])
        deadline = time.monotonic() + block_ms / 1000
        with self._condition:
            while len(self._events[job_id]) <= start:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return []
                self._condition.wait(remaining)
            items = self._events[job_id][start:]
            return [(f"{start + index + 1}-0", event) for index, event in enumerate(items)]
