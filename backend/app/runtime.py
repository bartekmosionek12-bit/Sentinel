"""Składanie zależności dla CLI, zadań Celery i API z ustawień aplikacji."""

from __future__ import annotations

from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import DbAuditSink
from app.core.config import Settings, get_settings
from app.core.db import get_sessionmaker
from app.core.scope_guard import ScopeConfig, ScopeGuard, SeedDemoApproval
from app.feeds.base import FeedSource, OfflineSource
from app.models import Software
from app.notifications.channels import ChannelSender
from app.pipeline import Rulebook
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
