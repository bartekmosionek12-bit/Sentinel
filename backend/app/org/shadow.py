"""Reguła shadow IT (#18, ARCHITECTURE §7.1).

Urządzenie jest nieznane, jeśli widziała je tylko sieć (skan, DHCP, DNS), a nie ma go w żadnym
źródle, które znaczy „organizacja o nim wie” (CSV, AD/Entra, MDM, CMDB, chmura), i nikt go nie
potwierdził. Nieznane urządzenie dostaje status `shadow` i finding typu `exposure`, który
przechodzi przez zwykłe reguły powiadomień. Gdy urządzenie trafi do CMDB albo człowiek je
potwierdzi, finding się zamyka.

Nie obiecujemy „zero shadow IT”: widzimy tylko to, co odpowiada w skanowanych sieciach albo
dostało adres z DHCP.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.inventory.sources import sources_of
from app.matching.engine import FindingChange, _record_change, _state
from app.models import Asset, AssetHistory, Finding
from app.models.base import utcnow
from app.models.organization import KNOWN_SOURCES
from app.scoring.engine import RiskInputs, ScoringConfig, score_risk

NON_DEVICE_TYPES = ("domain", "ip", "service", "application")
SOURCE_LABELS = {
    "scan": "skan sieci",
    "dhcp": "DHCP",
    "dns": "DNS",
    "csv": "import CSV",
    "ad": "Active Directory",
    "entra": "Entra ID",
    "mdm": "MDM",
    "cmdb": "CMDB",
    "cloud": "chmura",
}


def shadow_key(asset: Asset) -> str:
    return f"shadow:{asset.id}"


def evaluate_shadow(
    session: Session, scoring: ScoringConfig, *, now: datetime | None = None
) -> list[FindingChange]:
    """Przelicza status nieznanych urządzeń. Zwraca zmiany findingów do powiadomień."""
    now = now or utcnow()
    changes: list[FindingChange] = []
    assets = session.scalars(
        select(Asset).where(
            Asset.type.not_in(NON_DEVICE_TYPES), Asset.status.in_(("active", "shadow"))
        )
    ).all()
    for asset in assets:
        seen_by = sources_of(session, asset)
        if not seen_by:
            continue
        known = asset.confirmed or bool(seen_by & set(KNOWN_SOURCES))
        asset.in_cmdb = bool(seen_by & set(KNOWN_SOURCES))
        finding = session.scalar(select(Finding).where(Finding.dedup_key == shadow_key(asset)))
        if known:
            if asset.status == "shadow":
                asset.status = "active"
                session.add(
                    AssetHistory(
                        asset_id=asset.id,
                        change="updated",
                        diff={"status": {"before": "shadow", "after": "active"}},
                    )
                )
            if finding is not None and finding.status != "resolved":
                before = _state(finding)
                finding.status = "resolved"
                change = FindingChange(finding, "resolved", before, _state(finding))
                _record_change(
                    session,
                    change,
                    "Urządzenie potwierdzone przez człowieka"
                    if asset.confirmed
                    else "Urządzenie pojawiło się w źródle organizacji",
                )
                changes.append(change)
            continue

        if asset.status != "shadow":
            session.add(
                AssetHistory(
                    asset_id=asset.id,
                    change="updated",
                    diff={"status": {"before": asset.status, "after": "shadow"}},
                )
            )
            asset.status = "shadow"
        labels = sorted(SOURCE_LABELS.get(s, s) for s in seen_by)
        risk = score_risk(
            RiskInputs(exposure=asset.exposure, criticality=asset.criticality, severity="medium"),
            scoring,
        )
        evidence = {
            "rule": "shadow_it",
            "seen_by": sorted(seen_by),
            "summary": (
                f"Urządzenie widoczne w sieci ({', '.join(labels)}), a nie ma go w CMDB, AD ani MDM"
            ),
            "address": (asset.attributes or {}).get("address"),
        }
        # Opis dla menedżera: dlaczego to ryzyko, a nie sama formuła.
        breakdown = {
            **risk.breakdown,
            "summary": f"{risk.level.capitalize()}, bo: {evidence['summary']}",
        }
        if finding is None:
            finding = Finding(
                asset_id=asset.id,
                type="exposure",
                dedup_key=shadow_key(asset),
                risk_score=risk.score,
                risk_level=risk.level,
                risk_breakdown=breakdown,
                evidence=evidence,
                first_seen=now,
                last_seen=now,
            )
            session.add(finding)
            session.flush()
            change = FindingChange(finding, "created", after=_state(finding))
            _record_change(session, change, f"Nieznane urządzenie: {evidence['summary']}")
            changes.append(change)
        else:
            finding.last_seen = now
            finding.evidence = evidence
            if finding.status == "resolved":
                before = _state(finding)
                finding.status = "open"
                change = FindingChange(finding, "reopened", before, _state(finding))
                _record_change(session, change, "Urządzenie znowu nieznane")
                changes.append(change)
    session.flush()
    return changes
