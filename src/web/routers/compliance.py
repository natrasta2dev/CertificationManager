"""Routes conformité et rapports."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from ...core.compliance import ComplianceScanner
from ...core.reports import ReportGenerator
from ...core.users import User
from ..auth_deps import RequireOperator, RequireViewer
from ..dependencies import get_managers

router = APIRouter()


@router.get("/compliance/scan", response_class=JSONResponse)
async def scan_compliance(_: User = Depends(RequireViewer)):
    """Lance un scan de conformité sur tous les certificats."""
    managers = get_managers()
    try:
        scanner = ComplianceScanner(managers.storage)
        return {"success": True, "data": scanner.scan_all()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/compliance/scan/{cert_id}", response_class=JSONResponse)
async def scan_certificate_compliance(cert_id: str, _: User = Depends(RequireViewer)):
    """Scanne un certificat spécifique."""
    managers = get_managers()
    try:
        scanner = ComplianceScanner(managers.storage)
        ok, issues = scanner.scan_one(cert_id)
        return {"success": True, "data": {"valid": ok, "issues": issues}}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Certificat introuvable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/compliance/dashboard", response_class=JSONResponse)
async def compliance_dashboard(_: User = Depends(RequireViewer)):
    """Tableau de bord conformité Mozilla/NIST."""
    managers = get_managers()
    scanner = ComplianceScanner(managers.storage)
    return {"success": True, "data": scanner.guidelines_dashboard()}


@router.get("/reports/compliance.pdf")
async def export_compliance_pdf(_: User = Depends(RequireViewer)):
    managers = get_managers()
    scanner = ComplianceScanner(managers.storage)
    dashboard = scanner.guidelines_dashboard()
    pdf_bytes = ReportGenerator(managers.storage).compliance_pdf(dashboard)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=compliance.pdf"},
    )


@router.get("/reports/expiration.pdf")
async def export_expiration_pdf(_: User = Depends(RequireViewer)):
    managers = get_managers()
    certs = managers.storage.list_certificates()
    pdf_bytes = ReportGenerator(managers.storage).expiration_pdf(certs)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=expiration.pdf"},
    )


@router.get("/reports/audit.pdf")
async def export_audit_pdf(_: User = Depends(RequireViewer)):
    from ...core.audit import AuditLogger

    managers = get_managers()
    logs = AuditLogger(str(managers.storage.storage_path)).list_logs(limit=200)
    pdf_bytes = ReportGenerator(managers.storage).audit_pdf(logs)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=audit.pdf"},
    )


@router.get("/reports/certificates.csv", response_class=PlainTextResponse)
async def export_certificates_csv(_: User = Depends(RequireViewer)):
    """Export CSV de l'inventaire des certificats."""
    managers = get_managers()
    try:
        csv_data = ReportGenerator(managers.storage).certificates_csv()
        return PlainTextResponse(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=certificates.csv"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports/archives.csv", response_class=PlainTextResponse)
async def export_archives_csv(_: User = Depends(RequireViewer)):
    """Export CSV des certificats archivés."""
    managers = get_managers()
    try:
        csv_data = ReportGenerator(managers.storage).archives_csv()
        return PlainTextResponse(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=archives.csv"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
