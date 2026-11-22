"""Modele SQLAlchemy. Import tego pakietu rejestruje wszystkie tabele w Base.metadata."""

from app.models.agent import (
    AgentCapability,
    AgentConfigVersion,
    AgentStep,
    AgentSwitch,
    AgentTask,
    AgentTestCaseResult,
    AgentTestRun,
    CredentialLease,
)
from app.models.base import Base
from app.models.discovery import (
    CustomSignature,
    DefectDojoExport,
    DiscoveryBatch,
    DiscoveryRun,
    DiscoverySchedule,
    Observation,
    ObservationOverride,
)
from app.models.finding import Finding, FindingEvent, UpdateRecommendation
from app.models.iam import CustomRole, Permission, Role, RoleGrant, RolePermission, User
from app.models.inventory import (
    Asset,
    AssetHistory,
    AssetRelation,
    CpeProduct,
    MatchCandidate,
    SignalMatch,
    Software,
)
from app.models.network import AssetSource, NetworkSegment
from app.models.ops import (
    AuditLog,
    FeedSync,
    LLMCache,
    Notification,
    ScanAction,
    ScanRequest,
    ScanResultOverride,
    ScanRun,
    ScanTarget,
)
from app.models.report import Report, ReportDelivery, ReportRead
from app.models.threat import VulnAffected, Vulnerability

__all__ = [
    "AgentCapability",
    "AgentConfigVersion",
    "AgentStep",
    "AgentSwitch",
    "AgentTask",
    "AgentTestCaseResult",
    "AgentTestRun",
    "Asset",
    "AssetHistory",
    "AssetRelation",
    "AssetSource",
    "AuditLog",
    "Base",
    "CpeProduct",
    "CredentialLease",
    "CustomRole",
    "CustomSignature",
    "DefectDojoExport",
    "DiscoveryBatch",
    "DiscoveryRun",
    "DiscoverySchedule",
    "FeedSync",
    "Finding",
    "FindingEvent",
    "LLMCache",
    "MatchCandidate",
    "NetworkSegment",
    "Notification",
    "Observation",
    "ObservationOverride",
    "Permission",
    "Report",
    "ReportDelivery",
    "ReportRead",
    "Role",
    "RoleGrant",
    "RolePermission",
    "ScanAction",
    "ScanRequest",
    "ScanResultOverride",
    "ScanRun",
    "ScanTarget",
    "SignalMatch",
    "Software",
    "UpdateRecommendation",
    "User",
    "VulnAffected",
    "Vulnerability",
]
