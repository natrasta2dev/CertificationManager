"""Helpers pour journaliser les actions depuis l'API."""

from typing import Any, Dict, Optional

from starlette.requests import Request

from ..config import get_settings
from ..core.audit import AuditLogger
from ..core.users import User


def get_audit_logger() -> AuditLogger:
    settings = get_settings()
    return AuditLogger(
        storage_path=settings.storage_path,
        retention_days=settings.audit_retention_days,
    )


def audit_action(
    action: str,
    user: Optional[User],
    request: Optional[Request] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
) -> None:
    """Enregistre une action dans le journal d'audit."""
    ip_address = request.client.host if request and request.client else None
    get_audit_logger().log(
        action=action,
        user_id=user.id if user else "system",
        username=user.username if user else "system",
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        success=success,
        ip_address=ip_address,
    )
