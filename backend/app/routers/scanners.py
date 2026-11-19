import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.deps import require_roles
from app.models import Asset, User
from app.schemas import OpenVASImportRequest, ScannerImportOut, TrivyImportRequest
from app.services.audit import record_event
from app.services.scanners import parse_openvas_xml, parse_trivy, persist_findings

router = APIRouter(prefix="/scanners", tags=["scanner integrations"])
MAX_REPORT_BYTES = 8_000_000


@router.post("/trivy/import", response_model=ScannerImportOut)
def import_trivy(payload: TrivyImportRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    if len(json.dumps(payload.report, ensure_ascii=False).encode("utf-8")) > MAX_REPORT_BYTES:
        raise HTTPException(413, "Relatório Trivy excede o limite de 8 MB")
    asset = db.get(Asset, payload.asset_id)
    if asset is None:
        raise HTTPException(404, "Ativo alvo não encontrado")
    findings = parse_trivy(payload.report)
    if not findings:
        raise HTTPException(422, "Nenhuma vulnerabilidade CVE suportada foi encontrada no relatório Trivy")
    result = persist_findings(db, asset, "trivy", findings)
    record_event(db, user, "scanner.trivy_imported", "asset", asset.id, result, request)
    db.commit()
    return ScannerImportOut(scanner="trivy", asset_id=asset.id, vulnerabilities_created=result["created"], vulnerabilities_updated=result["updated"], **{"findings_seen": result["findings_seen"], "findings_ignored": result["ignored"]})


@router.post("/openvas/import", response_model=ScannerImportOut)
def import_openvas(payload: OpenVASImportRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    asset = db.get(Asset, payload.asset_id)
    if asset is None:
        raise HTTPException(404, "Ativo alvo não encontrado")
    try:
        findings = parse_openvas_xml(payload.report_xml)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not findings:
        raise HTTPException(422, "Nenhuma vulnerabilidade CVE suportada foi encontrada no relatório OpenVAS")
    result = persist_findings(db, asset, "openvas", findings)
    record_event(db, user, "scanner.openvas_imported", "asset", asset.id, result, request)
    db.commit()
    return ScannerImportOut(scanner="openvas", asset_id=asset.id, vulnerabilities_created=result["created"], vulnerabilities_updated=result["updated"], **{"findings_seen": result["findings_seen"], "findings_ignored": result["ignored"]})
