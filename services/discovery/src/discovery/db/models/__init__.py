"""ORM models package — import all models here so Alembic autogenerate picks them up."""
from discovery.db.models.apps import App
from discovery.db.models.audit_events import AuditEvent
from discovery.db.models.config_bundles import ConfigBundle
from discovery.db.models.credentials import Credential
from discovery.db.models.enrollment_tokens import EnrollmentToken
from discovery.db.models.sentinels import Sentinel, SentinelInstance
from discovery.db.models.services import Service
from discovery.db.models.status_lists import StatusList

__all__ = [
    "App",
    "AuditEvent",
    "ConfigBundle",
    "Credential",
    "EnrollmentToken",
    "Sentinel",
    "SentinelInstance",
    "Service",
    "StatusList",
]
