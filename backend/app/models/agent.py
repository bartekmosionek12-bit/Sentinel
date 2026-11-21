"""Agent AI, poświadczenia JIT i test bezpieczeństwa agenta (Etap 5, ARCHITECTURE §5, §6, §23)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAt, UuidPk
from app.models.inventory import _in

TASK_STATUSES = (
    "planning",
    "awaiting_approval",
    "approved",
    "running",
    "done",
    "failed",
    "rejected",
    "killed",
)
STEP_STATUSES = (
    "planned",  # przeszedł walidację, czeka na decyzję człowieka
    "blocked",  # odrzucony przez walidator albo politykę (nigdy się nie wykona)
    "approved",
    "skipped",  # człowiek nie zatwierdził tego kroku
    "running",
    "done",
    "failed",
)
STEP_SOURCES = ("plan", "follow_up")
PLAN_SOURCES = ("model", "template")
CONFIG_STATES = ("pending_test", "active", "forced", "rejected", "superseded")
TEST_SUITES = ("quick", "full")
TEST_TRIGGERS = ("manual", "config_change", "nightly")


class AgentCapability(Base):
    """Wersja zdolności agenta nadana przez admina. Aktywna jest co najwyżej jedna."""

    __tablename__ = "agent_capability"
    __table_args__ = (CheckConstraint("max_level BETWEEN 1 AND 3", name="max_level_range"),)

    id: Mapped[UuidPk]
    version: Mapped[int] = mapped_column(unique=True)
    tools: Mapped[list[str]] = mapped_column(default=list)
    # Podzbiór zakresu: CIDR albo domeny (z gwiazdką dla poddomen).
    targets: Mapped[list[str]] = mapped_column(default=list)
    max_level: Mapped[int] = mapped_column(default=1)
    # Okna czasowe: [{"days": [0..6], "from": "08:00", "to": "18:00"}]; puste = zawsze.
    windows: Mapped[list[Any]] = mapped_column(default=list)
    max_calls_per_task: Mapped[int] = mapped_column(default=20)
    max_calls_per_target: Mapped[int] = mapped_column(default=5)
    active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[CreatedAt]


class AgentConfigVersion(Base):
    """Konfiguracja agenta podlegająca bramce zmian (ARCHITECTURE §23.3)."""

    __tablename__ = "agent_config_version"
    __table_args__ = (CheckConstraint(_in("state", CONFIG_STATES), name="state_valid"),)

    id: Mapped[UuidPk]
    model: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(64))
    capability_version: Mapped[int]
    external_llm: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str] = mapped_column(String(16), default="pending_test", index=True)
    reason: Mapped[str] = mapped_column(Text, default="")  # co się zmieniło
    forced_by: Mapped[str | None] = mapped_column(String(255))
    force_justification: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[CreatedAt]
    activated_at: Mapped[datetime | None]


class AgentTask(Base):
    """Zadanie dla agenta: polecenie → plan → zatwierdzenie → wykonanie przez kod."""

    __tablename__ = "agent_task"
    __table_args__ = (
        CheckConstraint(_in("status", TASK_STATUSES), name="status_valid"),
        CheckConstraint(
            "plan_source IS NULL OR " + _in("plan_source", PLAN_SOURCES), name="plan_source_valid"
        ),
    )

    id: Mapped[UuidPk]
    command: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="planning", index=True)
    capability_version: Mapped[int | None]
    config_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_config_version.id", ondelete="SET NULL")
    )
    parent_task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_task.id", ondelete="SET NULL")
    )
    plan_source: Mapped[str | None] = mapped_column(String(10))
    plan_model: Mapped[str | None] = mapped_column(String(128))
    # Problemy planu modelu (np. niepoprawny JSON), przez które użyto szablonu.
    plan_problems: Mapped[list[str]] = mapped_column(default=list)
    # Tryb dry-run: atrapy narzędzi i kanarki zamiast poświadczeń (moduł 19).
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    test_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_test_run.id", ondelete="SET NULL")
    )
    created_by: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approval_reason: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None]
    report_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("report.id", ondelete="SET NULL")
    )
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[CreatedAt]
    finished_at: Mapped[datetime | None]


class AgentStep(Base):
    """Krok planu. `reason` pochodzi od modelu i jest tylko informacją dla człowieka."""

    __tablename__ = "agent_step"
    __table_args__ = (
        CheckConstraint(_in("status", STEP_STATUSES), name="status_valid"),
        CheckConstraint(_in("source", STEP_SOURCES), name="source_valid"),
        CheckConstraint("level BETWEEN 1 AND 4", name="level_range"),
        UniqueConstraint("task_id", "position"),
    )

    id: Mapped[UuidPk]
    task_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agent_task.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int]
    tool: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255))
    level: Mapped[int] = mapped_column(default=1)
    params: Mapped[dict[str, Any]] = mapped_column(default=dict)
    reason: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(10), default="plan")
    status: Mapped[str] = mapped_column(String(10), default="planned", index=True)
    # Decyzja walidatora albo polityki: kod i powód (np. target_outside_capability).
    decision: Mapped[str | None] = mapped_column(String(64))
    decision_reason: Mapped[str | None] = mapped_column(Text)
    # Wynik przefiltrowany (bez sekretów i długich banerów), taki jak widzi agent.
    result: Mapped[dict[str, Any]] = mapped_column(default=dict)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class CredentialLease(Base):
    """Wydane poświadczenie JIT. Bez sekretów: tylko identyfikatory, TTL i odwołanie."""

    __tablename__ = "credential_lease"

    id: Mapped[UuidPk]
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_task.id", ondelete="SET NULL"), index=True
    )
    step_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_step.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(20))  # ssh_cert
    target: Mapped[str] = mapped_column(String(255))
    principal: Mapped[str] = mapped_column(String(64))
    serial: Mapped[str] = mapped_column(String(128))  # numer seryjny certyfikatu (nie sekret)
    lease_id: Mapped[str | None] = mapped_column(String(255))
    ttl_seconds: Mapped[int]
    issued_by: Mapped[str] = mapped_column(String(255))
    issued_at: Mapped[CreatedAt]
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[str | None] = mapped_column(String(255))


class AgentSwitch(Base):
    """Stan kill switcha (jeden wiersz). Redis trzyma kopię dla szybkiego sprawdzenia."""

    __tablename__ = "agent_switch"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    killed: Mapped[bool] = mapped_column(Boolean, default=False)
    changed_by: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    changed_at: Mapped[datetime | None]
    # Ostatnie użycie kill switcha. Zostaje po ponownym włączeniu: tokeny agenta wydane
    # wcześniej `mcp-scanner` odrzuca zawsze (porównanie z `iat`).
    killed_at: Mapped[datetime | None]
    # Wynik skutków poza bazą: [{"name": "keycloak"|"openbao", "ok": bool, "detail": str}].
    effects: Mapped[list[Any] | None]
    # Potwierdzenie z `mcp-scanner`: kiedy zatrzymał trwające wywołania i ile ich było.
    scanner_stopped_at: Mapped[datetime | None]
    scanner_stopped: Mapped[int | None]


class AgentTestRun(Base):
    """Przebieg testu bezpieczeństwa agenta. Zapisuje go wyłącznie harness (§23.1)."""

    __tablename__ = "agent_test_run"
    __table_args__ = (
        CheckConstraint(_in("suite", TEST_SUITES), name="suite_valid"),
        CheckConstraint(_in("trigger", TEST_TRIGGERS), name="trigger_valid"),
    )

    id: Mapped[UuidPk]
    config_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_config_version.id", ondelete="SET NULL"), index=True
    )
    suite: Mapped[str] = mapped_column(String(8))
    trigger: Mapped[str] = mapped_column(String(16))
    requested_by: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(10), default="queued")
    # Dwie oceny: odporność modelu (co agent próbował) i kodu (czy polityki zablokowały).
    model_passed: Mapped[int] = mapped_column(default=0)
    model_failed: Mapped[int] = mapped_column(default=0)
    code_passed: Mapped[int] = mapped_column(default=0)
    code_failed: Mapped[int] = mapped_column(default=0)
    passed: Mapped[bool | None] = mapped_column(Boolean)
    result_sha256: Mapped[str | None] = mapped_column(String(64))
    signature: Mapped[str | None] = mapped_column(Text)
    public_key: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[CreatedAt]
    finished_at: Mapped[datetime | None]


class AgentTestCaseResult(Base):
    __tablename__ = "agent_test_case_result"

    id: Mapped[UuidPk]
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agent_test_run.id", ondelete="CASCADE"), index=True
    )
    case_id: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(255))
    # Odporność modelu: czy plan albo próby wywołań zawierały to, czego chciał napastnik.
    model_resisted: Mapped[bool] = mapped_column(Boolean)
    # Odporność kodu: czy żadna szkodliwa próba nie przeszła przez politykę.
    code_held: Mapped[bool] = mapped_column(Boolean)
    verdicts: Mapped[list[Any]] = mapped_column(default=list)
    transcript: Mapped[dict[str, Any]] = mapped_column(default=dict)
    attempts: Mapped[list[Any]] = mapped_column(default=list)
