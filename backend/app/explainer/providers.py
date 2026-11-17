"""Dostawcy modeli językowych. Jedyny moduł explainera z dostępem do sieci.

* `OllamaProvider`   domyślny, lokalny. Przyjmuje wyłącznie adres lokalny (nazwa usługi
                     Dockera, localhost albo prywatny adres IP) i nie używa proxy.
* `ExternalProvider` domyślnie wyłączony. Przyjmuje wyłącznie `AnonymizedPrompt`,
                     czyli tekst po przejściu przez anonimizator.
* `FakeProvider`     do testów i CI: bez modelu i bez sieci.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from app.explainer.anonymizer import AnonymizedPrompt
from app.explainer.prompts import Prompt

TEMPERATURE = 0.2


class ProviderError(Exception):
    """Model jest niedostępny albo odpowiedział w nieoczekiwany sposób."""


@dataclass(frozen=True)
class ProviderHealth:
    available: bool
    model: str
    detail: str


@dataclass(frozen=True)
class LLMResult:
    text: str
    model: str
    tokens: int | None
    duration_ms: int
    first_token_ms: int | None = None
    stats: dict[str, Any] = field(default_factory=dict)


class LLMProvider(Protocol):
    name: str
    model: str

    def stream(self, prompt: Prompt, *, max_tokens: int) -> Iterator[str]: ...

    def health(self) -> ProviderHealth: ...


def generate(
    provider: LLMProvider,
    prompt: Prompt,
    *,
    max_tokens: int,
    on_token: Callable[[str], None] | None = None,
) -> LLMResult:
    """Zbiera strumień w całość i mierzy czas. Wyjątki dostawcy przechodzą dalej."""
    started = time.monotonic()
    first: float | None = None
    parts: list[str] = []
    for chunk in provider.stream(prompt, max_tokens=max_tokens):
        if not chunk:
            continue
        if first is None:
            first = time.monotonic()
        parts.append(chunk)
        if on_token is not None:
            on_token(chunk)
    stats = dict(getattr(provider, "last_stats", {}) or {})
    tokens = stats.get("eval_count")
    return LLMResult(
        text="".join(parts).strip(),
        model=provider.model,
        tokens=int(tokens) if isinstance(tokens, int) else len(parts),
        duration_ms=int((time.monotonic() - started) * 1000),
        first_token_ms=int((first - started) * 1000) if first is not None else None,
        stats=stats,
    )


def is_local_url(url: str) -> bool:
    """Adres lokalny: nazwa usługi bez kropki, localhost albo prywatny adres IP.

    Sprawdzenie jest czysto tekstowe (bez DNS), żeby reguła była przewidywalna.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme not in {"http", "https"} or not host or parts.username or parts.password:
        return False
    try:
        address = ip_address(host)
    except ValueError:
        return host == "localhost" or "." not in host
    return address.is_loopback or address.is_private


def physical_cores() -> int:
    """Liczba fizycznych rdzeni (bez wątków HT) dostępnych dla procesu."""
    cores: set[tuple[str, str]] = set()
    physical = core = ""
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if key.strip() == "physical id":
                    physical = value.strip()
                elif key.strip() == "core id":
                    core = value.strip()
                elif not line.strip() and core:
                    cores.add((physical, core))
                    physical = core = ""
    except OSError:
        pass
    if core:
        cores.add((physical, core))
    available = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else 0
    count = len(cores) or available or os.cpu_count() or 1
    return max(1, min(count, available or count))


class _ThinkFilter:
    """Usuwa ze strumienia blok `<think>…</think>`, który dopisują niektóre modele."""

    OPEN, CLOSE = "<think>", "</think>"

    def __init__(self) -> None:
        self._buffer = ""
        self._inside = False

    def feed(self, chunk: str) -> str:
        self._buffer += chunk
        out: list[str] = []
        while self._buffer:
            marker = self.CLOSE if self._inside else self.OPEN
            index = self._buffer.find(marker)
            if index >= 0:
                if not self._inside:
                    out.append(self._buffer[:index])
                self._buffer = self._buffer[index + len(marker) :]
                self._inside = not self._inside
                continue
            # Zostaw w buforze końcówkę, która może być początkiem znacznika.
            keep = next(
                (n for n in range(len(marker) - 1, 0, -1) if self._buffer.endswith(marker[:n])), 0
            )
            if not self._inside:
                out.append(self._buffer[: len(self._buffer) - keep])
            self._buffer = self._buffer[len(self._buffer) - keep :] if keep else ""
            break
        return "".join(out)

    def flush(self) -> str:
        rest, self._buffer = ("" if self._inside else self._buffer), ""
        return rest


class OllamaProvider:
    name = "ollama"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        num_ctx: int = 4096,
        num_thread: int = 0,
        keep_alive: str = "-1",
        timeout: float = 300.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not is_local_url(base_url):
            raise ProviderError(
                "OLLAMA_URL musi wskazywać adres lokalny (nazwa usługi, localhost albo "
                "prywatny adres IP). Inferencja lokalna nie może wychodzić poza maszynę."
            )
        self._base_url = base_url.rstrip("/")
        self.model = model
        self._num_ctx = num_ctx
        self._num_thread = num_thread or physical_cores()
        self._keep_alive: str | int = (
            int(keep_alive) if keep_alive.lstrip("-").isdigit() else keep_alive
        )
        # trust_env=False: zapytanie do lokalnego modelu nigdy nie idzie przez proxy.
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(timeout, connect=5.0), follow_redirects=False, trust_env=False
        )
        self.last_stats: dict[str, Any] = {}

    def stream(self, prompt: Prompt, *, max_tokens: int) -> Iterator[str]:
        if not self.model:
            raise ProviderError("Model lokalny nie jest skonfigurowany (LLM_MODEL jest pusty)")
        self.last_stats = {}
        body = {
            "model": self.model,
            "stream": True,
            "think": False,
            "keep_alive": self._keep_alive,
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
            "options": {
                "num_ctx": self._num_ctx,
                "num_thread": self._num_thread,
                "num_predict": max_tokens,
                "temperature": TEMPERATURE,
                "seed": 7,
            },
        }
        think = _ThinkFilter()
        try:
            with self._client.stream("POST", f"{self._base_url}/api/chat", json=body) as response:
                if response.status_code != 200:
                    response.read()
                    raise ProviderError(f"Ollama: odpowiedź HTTP {response.status_code}")
                for line in response.iter_lines():
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(line)
                    except ValueError as error:
                        raise ProviderError("Ollama: odpowiedź nie jest JSON-em") from error
                    if event.get("error"):
                        raise ProviderError(f"Ollama: {str(event['error'])[:200]}")
                    text = think.feed(str((event.get("message") or {}).get("content") or ""))
                    if text:
                        yield text
                    if event.get("done"):
                        self.last_stats = {
                            key: event[key]
                            for key in (
                                "eval_count",
                                "eval_duration",
                                "prompt_eval_count",
                                "prompt_eval_duration",
                                "load_duration",
                                "total_duration",
                                "done_reason",
                            )
                            if key in event
                        }
                rest = think.flush()
                if rest:
                    yield rest
        except httpx.HTTPError as error:
            raise ProviderError(f"Ollama: błąd połączenia ({error.__class__.__name__})") from error

    def health(self) -> ProviderHealth:
        if not self.model:
            return ProviderHealth(False, "", "Model nie jest skonfigurowany (LLM_MODEL jest pusty)")
        try:
            response = self._client.get(f"{self._base_url}/api/tags", timeout=3.0)
            response.raise_for_status()
            models = [str(m.get("name", "")) for m in response.json().get("models", [])]
        except (httpx.HTTPError, ValueError, AttributeError):
            return ProviderHealth(False, self.model, "Usługa Ollama nie odpowiada")
        wanted = {self.model, f"{self.model}:latest"}
        if not wanted & set(models):
            return ProviderHealth(
                False, self.model, "Model nie jest pobrany (uruchom scripts/fetch_models.sh)"
            )
        return ProviderHealth(True, self.model, "Model lokalny gotowy")


class ExternalProvider:
    """Zewnętrzny model w protokole zgodnym z OpenAI (`/chat/completions`).

    Nie da się go wywołać zwykłym promptem: `stream` przyjmuje wyłącznie
    `AnonymizedPrompt`, który wydaje tylko `Anonymizer`.
    """

    name = "external"

    def __init__(
        self,
        *,
        enabled: bool,
        url: str,
        model: str,
        api_key: str,
        timeout: float = 120.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._enabled = enabled
        self._url = url.rstrip("/")
        self.model = model
        self._api_key = api_key
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=False)

    def _problem(self) -> str | None:
        if not self._enabled:
            return "Zewnętrzny model jest wyłączony (EXTERNAL_LLM_ENABLED=false)"
        parts = urlsplit(self._url)
        if parts.scheme != "https" or not parts.hostname:
            return "EXTERNAL_LLM_URL musi być adresem https"
        if not self.model or not self._api_key:
            return "Brak EXTERNAL_LLM_MODEL albo EXTERNAL_LLM_API_KEY"
        return None

    def stream(self, prompt: Prompt, *, max_tokens: int) -> Iterator[str]:
        if not isinstance(prompt, AnonymizedPrompt):
            raise TypeError("ExternalProvider przyjmuje wyłącznie AnonymizedPrompt z anonimizatora")
        problem = self._problem()
        if problem:
            raise ProviderError(problem)
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": TEMPERATURE,
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
        }
        try:
            response = self._client.post(
                f"{self._url}/chat/completions",
                json=body,
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        except httpx.HTTPError as error:
            raise ProviderError(
                f"Zewnętrzny model: błąd połączenia ({error.__class__.__name__})"
            ) from error
        if response.status_code != 200:
            raise ProviderError(f"Zewnętrzny model: odpowiedź HTTP {response.status_code}")
        try:
            yield str(response.json()["choices"][0]["message"]["content"])
        except (ValueError, KeyError, IndexError, TypeError) as error:
            raise ProviderError("Zewnętrzny model: nieoczekiwany format odpowiedzi") from error

    def health(self) -> ProviderHealth:
        problem = self._problem()
        return ProviderHealth(problem is None, self.model, problem or "Zewnętrzny model włączony")


class FakeProvider:
    """Zwraca przygotowane odpowiedzi po kolei. Zapamiętuje otrzymane prompty."""

    name = "fake"

    def __init__(
        self,
        responses: Sequence[str | Exception] = (),
        *,
        model: str = "fake-model",
        available: bool = True,
    ) -> None:
        self.model = model
        self._responses = list(responses)
        self._available = available
        self.prompts: list[Prompt] = []

    def stream(self, prompt: Prompt, *, max_tokens: int) -> Iterator[str]:
        self.prompts.append(prompt)
        if not self._responses:
            raise ProviderError("FakeProvider: brak przygotowanej odpowiedzi")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        words = response.split(" ")
        for index, word in enumerate(words):
            yield word if index == len(words) - 1 else word + " "

    def health(self) -> ProviderHealth:
        detail = "Atrapa modelu" if self._available else "Atrapa modelu: niedostępna"
        return ProviderHealth(self._available, self.model, detail)
