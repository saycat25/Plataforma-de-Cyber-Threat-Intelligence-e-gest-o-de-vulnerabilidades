import re

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.deps import require_roles
from app.models import Indicator, User, Vulnerability
from app.schemas import AnalysisOut, AnalysisRequest, FeedSyncOut
from app.services.audit import record_event
from app.services.deepseek import DeepSeekService, DeepSeekUnavailable
from app.services.feeds import FeedError, sync_cisa_kev, sync_nvd_cve

router = APIRouter(prefix="/intelligence", tags=["threat intelligence"])
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

@router.post("/feeds/cisa-kev/sync", response_model=FeedSyncOut)
async def cisa_kev_sync(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    try:
        result = await sync_cisa_kev(db)
    except FeedError as exc:
        raise HTTPException(502, str(exc)) from exc
    record_event(db, user, "feed.synced", "feed", "cisa-kev", result, request)
    db.commit()
    return FeedSyncOut(**result)

@router.post("/feeds/nvd/{cve_id}/sync")
async def nvd_sync(cve_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    cve_id = cve_id.upper()
    if not CVE_RE.fullmatch(cve_id):
        raise HTTPException(422, "Formato CVE inválido")
    try:
        result = await sync_nvd_cve(db, cve_id)
    except FeedError as exc:
        raise HTTPException(502, str(exc)) from exc
    record_event(db, user, "feed.nvd_cve_synced", "vulnerability", cve_id, result, request)
    db.commit()
    return result

@router.post("/analysis", response_model=AnalysisOut)
async def analyze(payload: AnalysisRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    vulnerabilities = list(db.scalars(select(Vulnerability).where(Vulnerability.id.in_(payload.vulnerability_ids))).all()) if payload.vulnerability_ids else []
    indicators = list(db.scalars(select(Indicator).where(Indicator.id.in_(payload.indicator_ids))).all()) if payload.indicator_ids else []
    evidence = {
        "vulnerabilities": [{"cve_id": v.cve_id, "title": v.title, "severity": v.severity, "cvss": v.cvss_score, "epss": v.epss_score, "kev": v.is_kev, "risk_score": v.risk_score, "status": v.status} for v in vulnerabilities],
        "indicators": [{"value": i.value, "type": i.indicator_type, "confidence": i.confidence, "tlp": i.tlp, "source": i.source} for i in indicators],
    }
    try:
        analysis = await DeepSeekService().analyze(payload.question, evidence)
    except DeepSeekUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    record_event(db, user, "ai.analysis_requested", "intelligence", None, {"vulnerability_count": len(vulnerabilities), "indicator_count": len(indicators)}, request)
    db.commit()
    from app.core.config import settings
    return AnalysisOut(model=settings.deepseek_model, analysis=analysis)
