"""Szyfrowanie pól wrażliwych w spoczynku (brief, wymaganie 16).

Kolumny z wynikami skanów, celami, nadpisaniami, dowodami, banerami i atrybutami zmieniają
typ na tekst, a istniejące wartości są szyfrowane kluczem z DATA_ENCRYPTION_KEY
(app/core/crypto.py). Ponowne uruchomienie pomija wartości już zaszyfrowane.

Revision ID: 0017
Revises: 0016
"""

import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.core.crypto import encrypt, is_encrypted

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (tabela, kolumna, czy JSON)
COLUMNS = (
    ("discovery_run", "targets", True),
    ("observation", "hostname", False),
    ("observation", "services", True),
    ("observation", "http", True),
    ("observation", "flags", True),
    ("observation_override", "value", True),
    ("finding", "evidence", True),
    ("asset", "attributes", True),
    ("software", "raw_banner", False),
)
JSONB = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    bind = op.get_bind()
    postgres = bind.dialect.name == "postgresql"
    for table, column, is_json in COLUMNS:
        if postgres:
            op.execute(
                sa.text(
                    f'ALTER TABLE "{table}" ALTER COLUMN "{column}" TYPE TEXT USING "{column}"::text'
                )
            )
        else:
            with op.batch_alter_table(table) as batch:
                batch.alter_column(column, type_=sa.Text())
        rows = bind.execute(
            sa.text(f'SELECT id, "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL')
        ).all()
        for row_id, value in rows:
            if is_encrypted(value):
                continue
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            if is_json:
                # Sprawdzenie, że to poprawny JSON, zanim zaszyfrujemy.
                json.loads(text)
            bind.execute(
                sa.text(f'UPDATE "{table}" SET "{column}" = :value WHERE id = :id'),
                {"value": encrypt(text), "id": row_id},
            )


def downgrade() -> None:
    from app.core.crypto import decrypt

    bind = op.get_bind()
    postgres = bind.dialect.name == "postgresql"
    for table, column, is_json in COLUMNS:
        rows = bind.execute(
            sa.text(f'SELECT id, "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL')
        ).all()
        for row_id, value in rows:
            bind.execute(
                sa.text(f'UPDATE "{table}" SET "{column}" = :value WHERE id = :id'),
                {"value": decrypt(value), "id": row_id},
            )
        target = "JSONB" if is_json else ("VARCHAR(255)" if column == "hostname" else "TEXT")
        if postgres:
            op.execute(
                sa.text(
                    f'ALTER TABLE "{table}" ALTER COLUMN "{column}" TYPE {target} '
                    f'USING "{column}"::{target.split("(")[0].lower()}'
                )
            )
        else:
            with op.batch_alter_table(table) as batch:
                batch.alter_column(column, type_=JSONB if is_json else sa.Text())
