"""Sygnały bez CPE: KEV podaje producenta i produkt, NVD jeszcze nie podał zakresu wersji.

Tak wygląda nowa, aktywnie wykorzystywana podatność w pierwszych godzinach: wpis w KEV jest,
konfiguracji CPE w NVD nie ma. Zwykłe dopasowanie (engine.py) jej nie widzi, bo nie ma czego
porównać z wersją. Ten moduł:

* porównuje producenta i produkt z KEV z oprogramowaniem w inwentarzu (alias i słownik CPE
  jak w zwykłym dopasowaniu, a w drugiej kolejności podobieństwo samych nazw),
* każde dopasowanie z pewnością od progu `review` zapisuje w kolejce weryfikacji. Finding
  powstaje WYŁĄCZNIE po decyzji człowieka, bo wersji nie da się sprawdzić,
* gdy NVD dopisze zakres wersji, czekające sygnały przechodzą w stan `superseded`, a
  potwierdzony sygnał zamyka się, kiedy zwykłe dopasowanie utworzy finding dla tej samej
  podatności na tym samym zasobie.

Wszystkie decyzje są deterministyczne i trafiają do dziennika audytu.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from rapidfuzz import fuzz
from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from app.core import audit
from app.inventory.service import UNKNOWN_PRODUCT
from app.matching.cpe import MatchingConfig, ProductNormalizer, normalize_name
from app.matching.engine import ACTIVE_STATUSES, FindingChange, MatchReport, _record_change, _state
from app.models import Asset, Finding, SignalMatch, Software, VulnAffected, Vulnerability
from app.models.base import utcnow
from app.scoring.engine import RiskInputs, ScoringConfig, score_risk

ACTOR = "rule:signals"
# Samo podobieństwo nazw (bez CPE) jest słabszym dowodem niż dopasowanie przez słownik.
NAME_ONLY_FACTOR = 0.9


@dataclass
class SignalReport:
    created: int = 0
    superseded: int = 0
    closed: int = 0


@dataclass(frozen=True)
class SignalScore:
    score: float
    method: str
    reason: str


def _software_names(software: Software) -> list[str]:
    names = [f"{software.vendor or ''} {software.product}"]
    if software.cpe_vendor and software.cpe_product:
        names.append(f"{software.cpe_vendor} {software.cpe_product}")
    return [normalize_name(n) for n in names if normalize_name(n)]


def score_signal(
    vendor: str, product: str, software: Software, normalizer: ProductNormalizer
) -> SignalScore | None:
    """Pewność, że produkt z KEV to ten program z inwentarza (0–1), z metodą i powodem."""
    best: SignalScore | None = None
    if software.cpe_vendor and software.cpe_product:
        resolution = normalizer.resolve(product, vendor=vendor)
        for candidate in resolution.candidates:
            if candidate.entry.key == (software.cpe_vendor, software.cpe_product):
                best = SignalScore(
                    round(candidate.score, 3),
                    "kev_cpe",
                    f"Produkt z KEV „{vendor} {product}” to w słowniku CPE "
                    f"{candidate.entry.vendor}:{candidate.entry.product} (metoda "
                    f"{candidate.method}, pewność {candidate.score:.2f}), a tak rozpoznano "
                    f"„{software.product}” w inwentarzu.",
                )
                break
    target = normalize_name(f"{vendor} {product}")
    for name in _software_names(software):
        ratio = fuzz.token_sort_ratio(target, name) / 100.0
        score = round(ratio * NAME_ONLY_FACTOR, 3)
        if best is None or score > best.score:
            best = SignalScore(
                score,
                "kev_name",
                f"Podobieństwo nazw „{vendor} {product}” i „{name}” {ratio:.2f} "
                f"× {NAME_ONLY_FACTOR} (bez CPE i bez wersji).",
            )
    return best


def match_signals(
    session: Session, normalizer: ProductNormalizer, config: MatchingConfig
) -> SignalReport:
    """Zapisuje nowe sygnały w kolejce i porządkuje te, które straciły sens."""
    report = SignalReport()
    has_cpe = exists().where(VulnAffected.vulnerability_id == Vulnerability.id)

    for signal in session.scalars(
        select(SignalMatch)
        .join(Vulnerability, SignalMatch.vulnerability_id == Vulnerability.id)
        .where(SignalMatch.decision == "pending", has_cpe)
    ):
        signal.decision = "superseded"
        signal.decided_by = ACTOR
        signal.decided_at = utcnow()
        report.superseded += 1
    report.closed = _close_confirmed(session)

    vulns = session.scalars(
        select(Vulnerability)
        .where(Vulnerability.kev_product.is_not(None), ~has_cpe)
        .order_by(Vulnerability.cve_id)
    ).all()
    if not vulns:
        session.flush()
        return report
    software_rows = session.scalars(
        select(Software).where(
            Software.product != UNKNOWN_PRODUCT, Software.match_status != "rejected"
        )
    ).all()
    known: set[tuple[uuid.UUID, uuid.UUID]] = {
        (v, s)
        for v, s in session.execute(select(SignalMatch.vulnerability_id, SignalMatch.software_id))
    }
    created: list[dict[str, object]] = []
    for vuln in vulns:
        vendor, product = vuln.kev_vendor_project or "", vuln.kev_product or ""
        for software in software_rows:
            if (vuln.id, software.id) in known:
                continue
            found = score_signal(vendor, product, software, normalizer)
            if found is None or found.score < config.review:
                continue
            session.add(
                SignalMatch(
                    vulnerability_id=vuln.id,
                    software_id=software.id,
                    source="kev",
                    vendor=vendor,
                    product=product,
                    score=found.score,
                    method=found.method,
                    reason=found.reason,
                )
            )
            known.add((vuln.id, software.id))
            report.created += 1
            created.append(
                {
                    "cve_id": vuln.cve_id,
                    "software": f"{software.product} {software.version}".strip(),
                    "score": found.score,
                    "method": found.method,
                }
            )
    session.flush()
    if created or report.superseded or report.closed:
        audit.record(
            session,
            audit.AuditEvent(
                actor=ACTOR,
                action="signals_matched",
                reason=(
                    f"Sygnały KEV bez zakresu wersji: do weryfikacji od pewności {config.review}; "
                    "finding powstaje wyłącznie po decyzji człowieka"
                ),
                inputs={
                    "created": created[:100],
                    "superseded": report.superseded,
                    "closed": report.closed,
                },
                object_type="signal",
            ),
        )
    return report


def _close_confirmed(session: Session) -> int:
    """Potwierdzony sygnał ustępuje findingowi CVE z prawdziwego dopasowania wersji."""
    closed = 0
    rows = session.execute(
        select(SignalMatch, Finding)
        .join(Finding, SignalMatch.finding_id == Finding.id)
        .where(SignalMatch.decision == "confirmed", Finding.status.in_(ACTIVE_STATUSES))
    ).all()
    for _signal, finding in rows:
        replaced = session.scalar(
            select(Finding.id).where(
                Finding.type == "cve",
                Finding.asset_id == finding.asset_id,
                Finding.vulnerability_id == finding.vulnerability_id,
                Finding.status.in_(ACTIVE_STATUSES),
            )
        )
        if replaced is None:
            continue
        before = _state(finding)
        finding.status = "resolved"
        _record_change(
            session,
            FindingChange(finding, "resolved", before, _state(finding)),
            "Sygnał z KEV zastąpiony findingiem z dopasowania wersji (NVD podał zakres)",
        )
        closed += 1
    return closed


class SignalError(Exception):
    """Decyzji nie da się zapisać."""


def decide_signal(
    session: Session,
    signal_id: uuid.UUID,
    *,
    accept: bool,
    decided_by: str,
    scoring: ScoringConfig,
) -> MatchReport:
    """Decyzja człowieka. Akceptacja tworzy finding typu `signal` z oceną ryzyka z kodu."""
    signal = session.get(SignalMatch, signal_id)
    if signal is None:
        raise SignalError("Nie znaleziono sygnału")
    if signal.decision != "pending":
        raise SignalError("Ten sygnał został już rozstrzygnięty")
    software = session.get(Software, signal.software_id)
    vuln = session.get(Vulnerability, signal.vulnerability_id)
    asset = session.get(Asset, software.asset_id) if software else None
    if software is None or vuln is None or asset is None:
        raise SignalError("Oprogramowanie albo podatność już nie istnieje")
    now = utcnow()
    signal.decision = "confirmed" if accept else "rejected"
    signal.decided_by = decided_by
    signal.decided_at = now
    report = MatchReport()
    if accept:
        risk = score_risk(
            RiskInputs(
                exposure=asset.exposure,
                criticality=asset.criticality,
                cvss=vuln.cvss_score,
                epss=vuln.epss,
                in_kev=vuln.in_kev,
                has_public_exploit=vuln.has_public_exploit,
            ),
            scoring,
        )
        finding = Finding(
            asset_id=asset.id,
            software_id=software.id,
            vulnerability_id=vuln.id,
            type="signal",
            dedup_key=f"signal:{asset.id}:{vuln.cve_id}:{software.id}",
            risk_score=risk.score,
            risk_level=risk.level,
            risk_breakdown=risk.breakdown,
            evidence={
                "cve_id": vuln.cve_id,
                "product": software.product,
                "version": software.version,
                "port": software.port,
                "signal_source": signal.source,
                "signal_vendor": signal.vendor,
                "signal_product": signal.product,
                "match_method": signal.method,
                "match_confidence": signal.score,
                "match_status": "confirmed",
                "version_check": "brak zakresu wersji w źródle; dopasowanie potwierdził człowiek",
                "confirmed_by": decided_by,
            },
            first_seen=now,
            last_seen=now,
        )
        session.add(finding)
        session.flush()
        signal.finding_id = finding.id
        change = FindingChange(finding, "created", after=_state(finding))
        _record_change(
            session,
            change,
            f"Sygnał KEV {vuln.cve_id} potwierdzony przez {decided_by} dla "
            f"{software.product} {software.version}. {risk.breakdown['summary']}",
        )
        report.changes.append(change)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=f"user:{decided_by}",
            action="signal_confirmed" if accept else "signal_rejected",
            reason="Decyzja człowieka w kolejce sygnałów bez CPE",
            inputs={
                "cve_id": vuln.cve_id,
                "software": f"{software.product} {software.version}".strip(),
                "score": signal.score,
                "method": signal.method,
            },
            object_type="signal",
            object_id=str(signal.id),
        ),
    )
    return report
