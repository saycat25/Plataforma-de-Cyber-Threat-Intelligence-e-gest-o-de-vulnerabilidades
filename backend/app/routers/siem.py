import hashlib
import hmac
import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.deps import get_current_user, require_roles
from app.models import Indicator, SIEMEvent, ThreatCorrelation, User, Vulnerability
from app.schemas import AnalysisOut, SIEMEventIn, SIEMEventOut, SIEMIngestOut, ThreatCorrelationOut
from app.services.audit import record_event
from app.services.deepseek import DeepSeekService, DeepSeekUnavailable
from app.services.siem import ingest_event, parse_cef

router = APIRouter(prefix="/siem", tags=["SIEM integration and threat correlation"])
MAX_EVENT_BYTES = 1_000_000


def _ingest_response(db: Session, payload: SIEMEventIn, actor: User | None, request: Request) -> SIEMIngestOut:
    event, correlation, duplicate = ingest_event(db, payload)
    if not duplicate:
        record_event(db, actor, "siem.event_ingested", "siem_event", event.id, {
            "source": event.source,
            "severity": event.severity,
            "correlation_score": correlation.score,
            "matched_indicators": len(correlation.matched_indicator_ids),
            "matched_vulnerabilities": len(correlation.matched_vulnerability_ids),
        }, request)
        db.commit()
        db.refresh(event)
        db.refresh(correlation)
    return SIEMIngestOut(
        event=SIEMEventOut.model_validate(event),
        duplicate=duplicate,
        correlation_score=correlation.score,
        matched_asset_ids=correlation.matched_asset_ids or [],
        matched_indicator_ids=correlation.matched_indicator_ids or [],
        matched_vulnerability_ids=correlation.matched_vulnerability_ids or [],
        rationale=correlation.rationale or [],
    )


@router.post("/events", response_model=SIEMIngestOut)
def ingest_authenticated_event(payload: SIEMEventIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    if len(json.dumps(payload.model_dump(mode="json"), ensure_ascii=False).encode("utf-8")) > MAX_EVENT_BYTES:
        raise HTTPException(413, "Evento excede o limite de 1 MB")
    try:
        return _ingest_response(db, payload, user, request)
    except Exception:
        db.rollback()
        raise


@router.post("/webhook", response_model=SIEMIngestOut)
async def ingest_signed_webhook(
    request: Request,
    db: Session = Depends(get_db),
    x_cti_signature: str | None = Header(default=None, alias="X-CTI-Signature"),
):
    """Receive JSON or CEF events signed with HMAC-SHA256."""
    if not settings.siem_webhook_secret:
        raise HTTPException(503, "SIEM_WEBHOOK_SECRET não configurado")
    body = await request.body()
    if len(body) > MAX_EVENT_BYTES:
        raise HTTPException(413, "Evento excede o limite de 1 MB")
    if not x_cti_signature:
        raise HTTPException(401, "Assinatura HMAC ausente")
    supplied = x_cti_signature.removeprefix("sha256=").strip().lower()
    expected = hmac.new(settings.siem_webhook_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(401, "Assinatura HMAC inválida")

    content_type = request.headers.get("content-type", "").lower()
    try:
        if "application/json" in content_type:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("Evento JSON precisa ser um objeto")
            payload = SIEMEventIn.model_validate(data)
            if not payload.raw_event:
                payload.raw_event = {"format": "JSON", "received_keys": sorted(data.keys())}
        elif "text/plain" in content_type or "application/cef" in content_type:
            payload = parse_cef(body.decode("utf-8"))
        else:
            raise HTTPException(415, "Content-Type deve ser application/json, text/plain ou application/cef")
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise HTTPException(422, "Payload SIEM inválido") from exc
    try:
        return _ingest_response(db, payload, None, request)
    except Exception:
        db.rollback()
        raise


@router.get("/events", response_model=list[SIEMEventOut])
def list_siem_events(limit: int = 100, offset: int = 0, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return list(db.scalars(select(SIEMEvent).order_by(SIEMEvent.occurred_at.desc()).offset(max(offset, 0)).limit(min(max(limit, 1), 200))).all())


@router.get("/correlations", response_model=list[ThreatCorrelationOut])
def list_correlations(limit: int = 100, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return list(db.scalars(select(ThreatCorrelation).order_by(ThreatCorrelation.created_at.desc()).limit(min(max(limit, 1), 200))).all())


@router.post("/correlations/{event_id}/analysis", response_model=AnalysisOut)
async def analyze_correlation(event_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    event = db.get(SIEMEvent, event_id)
    correlation = db.get(ThreatCorrelation, event_id)
    if event is None or correlation is None:
        raise HTTPException(404, "Correlação não encontrada")
    indicators = list(db.scalars(select(Indicator).where(Indicator.id.in_(correlation.matched_indicator_ids or []))).all())
    vulnerabilities = list(db.scalars(select(Vulnerability).where(Vulnerability.id.in_(correlation.matched_vulnerability_ids or []))).all())
    evidence = {
        "event": {
            "source": event.source,
            "event_type": event.event_type,
            "severity": event.severity,
            "occurred_at": event.occurred_at.isoformat(),
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "summary": event.summary,
        },
        "correlation": {
            "score": correlation.score,
            "matched_asset_ids": correlation.matched_asset_ids or [],
            "rationale": correlation.rationale,
        },
        "indicators": [{"value": item.value, "type": item.indicator_type, "confidence": item.confidence, "tlp": item.tlp, "source": item.source} for item in indicators],
        "vulnerabilities": [{"cve_id": item.cve_id, "title": item.title, "severity": item.severity, "cvss": item.cvss_score, "kev": item.is_kev, "risk_score": item.risk_score, "status": item.status} for item in vulnerabilities],
    }
    try:
        analysis = await DeepSeekService().analyze(
            "Analise esta correlação SIEM. Separe fatos confirmados, hipóteses, lacunas de telemetria e próximos passos defensivos de investigação. Não proponha exploração nem execução automática.",
            evidence,
        )
    except DeepSeekUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    record_event(db, user, "siem.correlation_analyzed", "siem_event", event.id, {"correlation_score": correlation.score}, request)
    db.commit()
    return AnalysisOut(model=settings.deepseek_model, analysis=analysis)
