"""Prywatność danych pracowników (ARCHITECTURE §15, #18).

- Imię i nazwisko widzi tylko ktoś z `personal_data:view`, i tylko gdy nie włączył
  pseudonimizacji (przełącznik w konsoli, np. na czas prezentacji).
- Eksporty (PDF, e-mail, CSV) i dane dla zewnętrznego LLM ZAWSZE dostają pseudonim
  „Pracownik #142”, niezależnie od uprawnień tego, kto eksportuje.
- Każdy podgląd danych osobowych zostaje w audycie: jeden wpis na żądanie API z listą
  identyfikatorów osób (bez nazwisk).
- W `DEMO_MODE` nazwiska są fikcyjne i konsola oznacza je etykietą „dane demonstracyjne”.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy.orm import Session

from app.core import audit
from app.models import Person

DEMO_LABEL = "dane demonstracyjne"


def pseudonym(person: Person) -> str:
    return f"Pracownik #{person.pseudonym_no}"


def person_view(person: Person, *, show_names: bool) -> dict[str, Any]:
    """Osoba w odpowiedzi API. Bez prawa do nazwisk: tylko pseudonim i status."""
    view: dict[str, Any] = {
        "id": str(person.id),
        "pseudonym": pseudonym(person),
        "active": person.active,
        "left_at": person.left_at.isoformat() if person.left_at else None,
    }
    if show_names:
        view["display_name"] = person.full_name
        view["job_title"] = person.job_title
    else:
        view["display_name"] = pseudonym(person)
        view["job_title"] = None
    return view


def record_personal_view(
    session: Session, *, actor: str, people: Iterable[Person], endpoint: str
) -> None:
    """Jeden wpis audytu na żądanie, które pokazało nazwiska. Bez nazwisk w samym wpisie."""
    ids = sorted({str(p.id) for p in people})
    if not ids:
        return
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="personal_data_viewed",
            reason=f"Podgląd danych osobowych: {endpoint}",
            inputs={"endpoint": endpoint, "people": ids, "count": len(ids)},
            object_type="person",
        ),
    )
