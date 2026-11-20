"""Modele SQLAlchemy. Import tego pakietu rejestruje wszystkie tabele w Base.metadata."""

from app.models.base import Base
from app.models.finding import (
    ComplianceResult,
    ComplianceRule,
    Finding,
    FindingEvent,
    UpdateRecommendation,
)
from app.models.iam import Permission, Role, RolePermission, User
from app.models.inventory import (
    Asset,
    AssetHistory,
    AssetRelation,
    CpeProduct,
    MatchCandidate,
    Software,
)
from app.models.ops import (
    AuditLog,
    FeedSync,
    LLMCache,
    Notification,
    ScanAction,
    ScanRun,
)
from app.models.report import Report, ReportDelivery, ReportRead
from app.models.threat import VulnAffected, Vulnerability

__all__ = [
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
    "Permission",
    "Report",
    "ReportDelivery",
    "ReportRead",
    "Role",
    "RolePermission",
    "ScanAction",
    "ScanRun",
    "Software",
    "UpdateRecommendation",
    "User",
    "VulnAffected",
    "Vulnerability",
]
