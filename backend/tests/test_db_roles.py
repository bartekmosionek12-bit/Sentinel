"""Osobni użytkownicy bazy dla aplikacji i Keycloaka (infra/postgres/init_roles.sql).

Wymaga PostgreSQL z rolami założonymi przez init_roles.sql, dlatego działa tylko w zadaniu CI
z prawdziwą bazą (i lokalnie po ustawieniu zmiennych poniżej). Bez nich test jest pomijany.

    SENTINEL_TEST_APP_DB_URL       postgresql+psycopg://sentinel_app:...@host/sentinel
    SENTINEL_TEST_KEYCLOAK_DB_URL  postgresql+psycopg://keycloak:...@host/sentinel
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import ProgrammingError

APP_URL = os.environ.get("SENTINEL_TEST_APP_DB_URL", "")
KEYCLOAK_URL = os.environ.get("SENTINEL_TEST_KEYCLOAK_DB_URL", "")
HARNESS_URL = os.environ.get("SENTINEL_TEST_HARNESS_DB_URL", "")

pytestmark = pytest.mark.skipif(
    not (APP_URL and KEYCLOAK_URL), reason="wymaga PostgreSQL z rolami z init_roles.sql"
)


@pytest.fixture(scope="module")
def app_db() -> Iterator[Engine]:
    engine = create_engine(APP_URL)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def keycloak_db() -> Iterator[Engine]:
    engine = create_engine(KEYCLOAK_URL)
    with engine.begin() as conn:
        # Tabela w schemacie Keycloaka z „tajną” wartością, jak tabele credential Keycloaka.
        conn.execute(text("CREATE TABLE IF NOT EXISTS keycloak.probe_credential (secret text)"))
        conn.execute(text("DELETE FROM keycloak.probe_credential"))
        conn.execute(text("INSERT INTO keycloak.probe_credential VALUES ('kanarek')"))
    yield engine
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE keycloak.probe_credential"))
    engine.dispose()


def _denied(engine: Engine, sql: str) -> None:
    with engine.connect() as conn, pytest.raises(ProgrammingError, match="permission denied"):
        conn.execute(text(sql))


def test_app_user_cannot_read_keycloak_schema(app_db: Engine, keycloak_db: Engine) -> None:
    _denied(app_db, "SELECT secret FROM keycloak.probe_credential")


def test_app_user_cannot_write_or_create_in_keycloak_schema(
    app_db: Engine, keycloak_db: Engine
) -> None:
    _denied(app_db, "INSERT INTO keycloak.probe_credential VALUES ('x')")
    _denied(app_db, "CREATE TABLE keycloak.app_table (id int)")
    _denied(app_db, "CREATE SCHEMA app_extra")


def test_keycloak_user_cannot_read_application_schema(keycloak_db: Engine) -> None:
    _denied(keycloak_db, "SELECT * FROM public.audit_log")
    _denied(keycloak_db, "SELECT * FROM public.iam_user")
    _denied(keycloak_db, "CREATE TABLE public.kc_table (id int)")


def test_users_are_not_superusers_and_own_only_their_schema(
    app_db: Engine, keycloak_db: Engine
) -> None:
    query = text(
        "SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user"
    )
    owned = text(
        "SELECT nspname FROM pg_namespace WHERE nspowner = "
        "(SELECT oid FROM pg_roles WHERE rolname = current_user) ORDER BY 1"
    )
    for engine, schema in ((app_db, "public"), (keycloak_db, "keycloak")):
        with engine.connect() as conn:
            assert tuple(conn.execute(query).one()) == (False, False, False)
            assert [row[0] for row in conn.execute(owned)] == [schema]


def test_app_user_still_reads_its_own_tables(app_db: Engine) -> None:
    with app_db.connect() as conn:
        conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one()


needs_harness = pytest.mark.skipif(not HARNESS_URL, reason="wymaga użytkownika harnessu")


@pytest.fixture(scope="module")
def harness_db() -> Iterator[Engine]:
    engine = create_engine(HARNESS_URL)
    yield engine
    engine.dispose()


_INSERT_RUN = (
    "INSERT INTO agent_test_run (id, suite, trigger, requested_by, status, model_passed, "
    "model_failed, code_passed, code_failed, created_at) VALUES (gen_random_uuid(), 'quick', "
    "'manual', 'test', 'done', 0, 0, 0, 0, now())"
)


@needs_harness
def test_app_user_reads_but_cannot_change_agent_test_results(
    app_db: Engine, harness_db: Engine
) -> None:
    """Moduł 19: ani agent, ani API (użytkownik aplikacji) nie zmienią wyniku testu."""
    with harness_db.begin() as conn:
        conn.execute(text(_INSERT_RUN))
    with app_db.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM agent_test_run")).scalar_one() >= 1
    _denied(app_db, _INSERT_RUN)
    _denied(app_db, "UPDATE agent_test_run SET passed = true")
    _denied(app_db, "DELETE FROM agent_test_case_result")


@needs_harness
def test_harness_user_sees_only_what_the_gate_needs(harness_db: Engine) -> None:
    _denied(harness_db, "SELECT * FROM asset")
    _denied(harness_db, "SELECT * FROM iam_user")
    _denied(harness_db, "DELETE FROM audit_log")
    _denied(harness_db, "SELECT * FROM keycloak.probe_credential")
    with harness_db.connect() as conn:
        conn.execute(text("SELECT count(*) FROM agent_config_version")).scalar_one()
