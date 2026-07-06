"""Endpoint métriques Prometheus."""

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from ...core.users import User
from ..auth_deps import RequireViewer
from ..dependencies import get_managers

router = APIRouter()


@router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics(_: User = Depends(RequireViewer)):
    """Expose des métriques au format Prometheus."""
    managers = get_managers()
    stats = managers.lifecycle.get_statistics()
    lines = [
        "# HELP certmanager_certificates_total Nombre total de certificats",
        "# TYPE certmanager_certificates_total gauge",
        f"certmanager_certificates_total {stats.get('total', 0)}",
        "# HELP certmanager_certificates_valid Certificats valides",
        "# TYPE certmanager_certificates_valid gauge",
        f"certmanager_certificates_valid {stats.get('valid', 0)}",
        "# HELP certmanager_certificates_expired Certificats expirés",
        "# TYPE certmanager_certificates_expired gauge",
        f"certmanager_certificates_expired {stats.get('expired', 0)}",
        "# HELP certmanager_certificates_expiring_soon Expirent dans 30 jours",
        "# TYPE certmanager_certificates_expiring_soon gauge",
        f"certmanager_certificates_expiring_soon {stats.get('expiring_soon', 0)}",
        "# HELP certmanager_certificates_critical Expirent dans 7 jours",
        "# TYPE certmanager_certificates_critical gauge",
        f"certmanager_certificates_critical {stats.get('critical', 0)}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
