"""Routes configuration notifications et webhooks."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ...core.notifications import EmailNotifier
from ...core.scheduler import SchedulerService
from ...core.users import User
from ...core.webhooks import WEBHOOK_EVENTS, WebhookManager
from ..auth_deps import RequireAdmin, RequireOperator, RequireViewer
from ..dependencies import get_managers

router = APIRouter()


class NotificationConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    use_tls: Optional[bool] = None
    from_email: Optional[str] = None
    to_emails: Optional[list] = None


class WebhookConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    secret: Optional[str] = None
    endpoints: Optional[list] = None


class SchedulerConfigUpdate(BaseModel):
    interval_minutes: Optional[int] = None
    auto_renew_enabled: Optional[bool] = None
    auto_renew_days: Optional[int] = None
    alert_email_enabled: Optional[bool] = None
    alert_webhook_enabled: Optional[bool] = None


@router.get("/notifications/config", response_class=JSONResponse)
async def get_notification_config(_: User = Depends(RequireViewer)):
    managers = get_managers()
    cfg = EmailNotifier(str(managers.storage.storage_path)).get_config()
    safe = {**cfg}
    if safe.get("smtp_password"):
        safe["smtp_password"] = "***"
    return {"success": True, "data": safe}


@router.put("/notifications/config", response_class=JSONResponse)
async def update_notification_config(
    body: NotificationConfigUpdate,
    _: User = Depends(RequireAdmin),
):
    managers = get_managers()
    notifier = EmailNotifier(str(managers.storage.storage_path))
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    cfg = notifier.update_config(updates)
    if cfg.get("smtp_password"):
        cfg["smtp_password"] = "***"
    return {"success": True, "data": cfg}


@router.get("/webhooks/config", response_class=JSONResponse)
async def get_webhook_config(_: User = Depends(RequireViewer)):
    managers = get_managers()
    cfg = WebhookManager(str(managers.storage.storage_path)).get_config()
    safe = {**cfg}
    if safe.get("secret"):
        safe["secret"] = "***"
    return {"success": True, "data": safe, "events": sorted(WEBHOOK_EVENTS)}


@router.put("/webhooks/config", response_class=JSONResponse)
async def update_webhook_config(
    body: WebhookConfigUpdate,
    _: User = Depends(RequireAdmin),
):
    managers = get_managers()
    wh = WebhookManager(str(managers.storage.storage_path))
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    cfg = wh.update_config(updates)
    if cfg.get("secret"):
        cfg["secret"] = "***"
    return {"success": True, "data": cfg}


@router.get("/scheduler/status", response_class=JSONResponse)
async def scheduler_status(_: User = Depends(RequireViewer)):
    managers = get_managers()
    status = SchedulerService(str(managers.storage.storage_path)).get_status()
    return {"success": True, "data": status}


@router.put("/scheduler/config", response_class=JSONResponse)
async def update_scheduler_config(
    body: SchedulerConfigUpdate,
    _: User = Depends(RequireAdmin),
):
    managers = get_managers()
    sched = SchedulerService(str(managers.storage.storage_path))
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    return {"success": True, "data": sched.update_config(updates)}


@router.post("/scheduler/run/{job_name}", response_class=JSONResponse)
async def run_scheduler_job(job_name: str, _: User = Depends(RequireOperator)):
    managers = get_managers()
    sched = SchedulerService(str(managers.storage.storage_path))
    try:
        result = sched.run_job(job_name)
        return {"success": True, "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
