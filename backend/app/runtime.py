"""Składanie zależności dla CLI, zadań Celery i API z ustawień aplikacji."""

from __future__ import annotations

from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import DbAuditSink
from app.core.config import Settings, get_settings
from app.core.db import get_sessionmaker
from app.core.scope_guard import ScopeConfig, ScopeGuard, SeedDemoApproval
from app.explainer.context import ExplainerConfig, product_titles
from app.explainer.providers import ExternalProvider, LLMProvider, OllamaProvider
from app.explainer.service import ExplainerService
from app.explainer.stream import EventBus, RedisEventBus
from app.feeds.base import FeedSource, OfflineSource
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
