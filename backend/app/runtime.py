"""Składanie zależności dla CLI, zadań Celery i API z ustawień aplikacji."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Sequence
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.gateway import ToolGateway
from app.agent.planner import Planner
from app.agent.service import AgentService
from app.agent_tests.gate import RuntimeConfig, config_ready, runtime_config
from app.core.audit import DbAuditSink
from app.core.config import Settings, get_settings
from app.core.db import get_sessionmaker
from app.core.scope_guard import ScopeConfig, ScopeGuard, SeedDemoApproval
from app.explainer.context import ExplainerConfig, product_titles
from app.explainer.providers import ExternalProvider, LLMProvider, OllamaProvider
from app.explainer.service import ExplainerService
from app.explainer.stream import EventBus, RedisEventBus
from app.feeds.base import FeedSource, OfflineSource
from app.mcp_server.runtime import Toolbox
from app.models import Software
from app.notifications.channels import ChannelSender
from app.pipeline import Rulebook
from app.reports.config import ReportsConfig
from app.scans.service import ScanService


def build_scope_guard(settings: Settings) -> ScopeGuard:
    return ScopeGuard(
        ScopeConfig.from_file(settings.scope_file),
        audit=DbAuditSink(get_sessionmaker()),
        seed_demo=SeedDemoApproval(
            demo_mode=settings.demo_mode,
            lab_network=settings.demo_lab_network,
            expires_at=settings.demo_approval_expires_at,
        ),
    )


@lru_cache
def get_scope_guard() -> ScopeGuard:
    return build_scope_guard(get_settings())


@lru_cache
def get_rulebook() -> Rulebook:
    return Rulebook.from_dir(get_settings().rules_dir)


def channel_sender() -> ChannelSender:
    return ChannelSender(get_settings())


def scan_service(session: Session) -> ScanService:
    return ScanService(session, get_scope_guard(), get_rulebook(), sender=channel_sender())


def feed_source(session: Session, settings: Settings) -> FeedSource:
    """Offline (domyślnie): snapshoty z dysku. Online: tylko po świadomym włączeniu."""
    if settings.feeds_mode != "online":
        return OfflineSource(settings.feeds_dir)
    from app.feeds.http import OnlineSource

    products = [
        (str(vendor), str(product))
        for vendor, product in session.execute(
            select(Software.cpe_vendor, Software.cpe_product)
            .where(Software.cpe_vendor.is_not(None), Software.cpe_product.is_not(None))
            .distinct()
        )
    ]
    return OnlineSource(nvd_api_key=settings.nvd_api_key, products=products)


@lru_cache
def get_reports_config() -> ReportsConfig:
    return ReportsConfig.from_dir(get_settings().rules_dir)


@lru_cache
def get_explainer_config() -> ExplainerConfig:
    return ExplainerConfig.from_file(get_settings().rules_dir / "explainer.yaml")


def local_provider(settings: Settings) -> LLMProvider | None:
    """Model lokalny. Pusty LLM_MODEL oznacza pracę bez modelu (wyjaśnienia z szablonu)."""
    if not settings.llm_model.strip():
        return None
    return OllamaProvider(
        base_url=settings.ollama_url,
        model=settings.llm_model.strip(),
        num_ctx=settings.llm_num_ctx,
        num_thread=settings.llm_num_thread,
        keep_alive=settings.ollama_keep_alive,
        timeout=settings.llm_timeout_seconds,
    )


def external_provider(settings: Settings) -> LLMProvider | None:
    """Zewnętrzny model istnieje tylko po świadomym włączeniu przez administratora."""
    if not settings.external_llm_enabled:
        return None
    return ExternalProvider(
        enabled=True,
        url=settings.external_llm_url,
        model=settings.external_llm_model,
        api_key=settings.external_llm_api_key,
    )


def explainer_service(session: Session) -> ExplainerService:
    settings = get_settings()
    return ExplainerService(
        session,
        get_explainer_config(),
        provider=local_provider(settings),
        external=external_provider(settings),
        titles=product_titles(get_rulebook().aliases),
    )


@lru_cache
def get_event_bus() -> EventBus:
    return RedisEventBus(get_settings().redis_url)


def mcp_toolbox(settings: Settings) -> Toolbox:
    """Adaptery narzędzi dla `mcp-scanner`. OpenBao i nuclei są opcjonalne."""
    from app.credentials.openbao import OpenBao
    from app.scanners.http_probe import HttpProber
    from app.scanners.nmap import NmapAdapter
    from app.scanners.nuclei import NucleiAdapter, NucleiConfig
    from app.scanners.ssh import ParamikoConnector

    nuclei = (
        NucleiAdapter(NucleiConfig.from_file(settings.nuclei_config))
        if settings.nuclei_config.exists()
        else None
    )
    role_id, secret_id = settings.openbao_role_id, settings.openbao_secret_id
    if settings.openbao_url and not role_id and settings.openbao_approle_file.exists():
        approle = json.loads(settings.openbao_approle_file.read_text(encoding="utf-8"))
        role_id, secret_id = str(approle["role_id"]), str(approle["secret_id"])
    vault = (
        OpenBao(url=settings.openbao_url, role_id=role_id, secret_id=secret_id)
        if settings.openbao_url and role_id
        else None
    )
    return Toolbox(
        nmap=NmapAdapter(),
        http=HttpProber(),
        nuclei=nuclei,
        ssh=ParamikoConnector(settings.ssh_known_hosts) if vault else None,
        vault=vault,
        ssh_username=settings.ssh_username,
    )


def agent_runtime_config(settings: Settings) -> RuntimeConfig:
    return runtime_config(settings.llm_model, settings.external_llm_enabled)


def enqueue_agent_test(config_version_id: uuid.UUID) -> None:
    from app.workers.tasks import run_agent_test

    run_agent_test.delay(
        suite="quick",
        trigger="config_change",
        requested_by="system:agent-config",
        config_version_id=str(config_version_id),
    )


def nuclei_templates(settings: Settings) -> Callable[[str], Sequence[str]] | None:
    from app.scanners.nuclei import NucleiConfig

    if not settings.nuclei_config.exists():
        return None
    config = NucleiConfig.from_file(settings.nuclei_config)
    return lambda cve: config.templates.get(cve.upper(), ())


def agent_service(session: Session) -> AgentService:
    settings = get_settings()
    config = agent_runtime_config(settings)
    return AgentService(
        session,
        get_scope_guard(),
        Planner(local_provider(settings)),
        templates_for=nuclei_templates(settings),
        config_ready=lambda s: config_ready(s, config, enqueue_agent_test),
    )


def agent_gateway(settings: Settings) -> ToolGateway:
    from app.agent.gateway import ClientCredentials, McpGateway

    return McpGateway(
        settings.mcp_url,
        ClientCredentials(
            settings.oidc_token_url, settings.agent_client_id, settings.agent_client_secret
        ),
    )
