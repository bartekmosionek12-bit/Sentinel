# Obraz backendu: API i workery Celery. Kontekst budowania: katalog główny repo.

# --- etap budowania: uv instaluje zależności do /opt/venv i nie trafia do obrazu końcowego
FROM python:3.12-slim AS build

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv

RUN pip install --no-cache-dir uv==0.13.8

WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# --- obraz bazowy: API i workery bez dostępu do celów skanowania
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Poprawki bezpieczeństwa pakietów systemowych wydane po zbudowaniu obrazu bazowego.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    # WeasyPrint (PDF raportów): Pango z HarfBuzz i fonty z polskimi znakami.
    && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 \
       libharfbuzz-subset0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home sentinel

COPY --from=build /opt/venv /opt/venv

WORKDIR /app/backend
COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/app ./app
COPY rules /app/rules
# Katalog na klucz podpisu harnessu (moduł 19); wolumen dziedziczy właściciela przy tworzeniu.
RUN mkdir -p /app/data/harness && chown 10001 /app/data/harness && chmod 700 /app/data/harness

USER 10001

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# --- obraz skanera: jedyny z narzędziami skanującymi, używa go wyłącznie worker-scans
FROM runtime AS scanner
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*
USER 10001
CMD ["celery", "-A", "app.workers.celery_app", "worker", "-Q", "scans", "-c", "2", "--loglevel", "INFO"]
