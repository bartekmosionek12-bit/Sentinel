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
    SignalMatch,
    Software,
)
from app.models.ops import (
    AuditLog,
    FeedSync,
    LLMCache,
    Notification,
    ScanAction,
    ScanRequest,
    ScanRun,
)
from app.models.organization import (
    AssetAssignment,
    AssetSource,
    CoverageSnapshot,
    Location,
    NetworkSegment,
    OrgUnit,
    Person,
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
    "AssetAssignment",
    "AssetHistory",
    "AssetRelation",
    "AssetSource",
    "AuditLog",
    "Base",
    "ComplianceResult",
    "ComplianceRule",
    "CoverageSnapshot",
    "CpeProduct",
    "CredentialLease",
    "FeedSync",
    "Finding",
    "FindingEvent",
    "LLMCache",
    "Location",
    "MatchCandidate",
    "NetworkSegment",
    "Notification",
    "OrgUnit",
    "Permission",
    "Person",
    "Report",
    "ReportDelivery",
    "ReportRead",
    "Role",
    "RolePermission",
    "ScanAction",
    "ScanRequest",
    "ScanRun",
    "SignalMatch",
    "Software",
    "UpdateRecommendation",
    "User",
    "VulnAffected",
    "Vulnerability",
]
