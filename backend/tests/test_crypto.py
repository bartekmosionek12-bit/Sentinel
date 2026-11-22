"""Szyfrowanie pól wrażliwych w spoczynku: w bazie leży szyfrogram, aplikacja widzi wartości."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import get_settings
from app.models import DiscoveryRun, Observation, ObservationOverride


def test_scan_results_are_encrypted_in_the_database(session: Session) -> None:
    run = DiscoveryRun(name="r", status="done", targets=["10.20.0.0/24"])
    session.add(run)
    session.flush()
    session.add(
        Observation(
            run_id=run.id,
            ip="10.20.0.5",
            hostname="gitea.wewn",
            services=[{"port": 3001, "product": "Gitea"}],
            http=[{"port": 3001, "title": "Gitea"}],
            flags=[{"kind": "panel", "evidence": ["/user/login"]}],
        )
    )
    session.add(ObservationOverride(ip="10.20.0.5", field="note", value="tajna", updated_by="t"))
    session.commit()
    raw = session.execute(text("SELECT hostname, services, http, flags FROM observation")).one()
    for value in raw:
        assert value.startswith(crypto.PREFIX)
        assert "gitea" not in value.lower()
    assert (
        session.execute(text("SELECT targets FROM discovery_run"))
        .scalar_one()
        .startswith(crypto.PREFIX)
    )
    assert session.execute(text("SELECT value FROM observation_override")).scalar_one() != "tajna"
    session.expire_all()
    obs = session.scalars(select(Observation)).one()
    assert obs.hostname == "gitea.wewn"
    assert obs.services[0]["product"] == "Gitea"
    assert session.scalars(select(DiscoveryRun)).one().targets == ["10.20.0.0/24"]


def test_plaintext_from_before_migration_is_still_readable() -> None:
    assert crypto.decrypt('[{"port": 22}]') == '[{"port": 22}]'


def test_key_rotation_and_wrong_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", "stary-klucz")
    get_settings.cache_clear()
    crypto.cipher.cache_clear()
    old = crypto.encrypt("dane")
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", "nowy-klucz")
    monkeypatch.setenv("DATA_ENCRYPTION_KEYS_OLD", "stary-klucz")
    get_settings.cache_clear()
    crypto.cipher.cache_clear()
    assert crypto.decrypt(old) == "dane"
    monkeypatch.setenv("DATA_ENCRYPTION_KEYS_OLD", "")
    get_settings.cache_clear()
    crypto.cipher.cache_clear()
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(old)
    monkeypatch.delenv("DATA_ENCRYPTION_KEY")
    monkeypatch.delenv("DATA_ENCRYPTION_KEYS_OLD")
    get_settings.cache_clear()
    crypto.cipher.cache_clear()
