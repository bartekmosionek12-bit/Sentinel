"""Modele SQLAlchemy. Import tego pakietu rejestruje wszystkie tabele w Base.metadata."""

from app.models.base import Base
from app.models.finding import (
    ComplianceResult,
    ComplianceRule,
    Finding,
    FindingEvent,
    UpdateRecommendation,
)
from app.models.inventory import (
    Asset,
    AssetHistory,
    AssetRelation,
    CpeProduct,
    MatchCandidate,
    Software,
)
from app.models.ops import (
    AppUser,
    AuditLog,
    FeedSync,
    LLMCache,
    Notification,
    ScanAction,
    ScanRun,
)
from app.models.threat import VulnAffected, Vulnerability

__all__ = [
    "AppUser",
    "Asset",
    "AssetHistory",
    "AssetRelation",
    "AuditLog",
    "Base",
    "ComplianceResult",
    "ComplianceRule",
    "CpeProduct",
    "FeedSync",
    "Finding",
    "FindingEvent",
    "LLMCache",
    "MatchCandidate",
    "Notification",
    "ScanAction",
    "ScanRun",
    "Software",
    "UpdateRecommendation",
    "VulnAffected",
    "Vulnerability",
]
