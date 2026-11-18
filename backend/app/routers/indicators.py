from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.deps import get_current_user, require_roles
from app.models import Indicator, User
from app.schemas import IndicatorCreate, IndicatorOut, IndicatorUpdate
from app.services.audit import record_event
from app.services.indicators import normalize_indicator

router = APIRouter(prefix="/indicators", tags=["threat indicators"])

@router.get("", response_model=list[IndicatorOut])
def list_indicators(limit: int = 100, offset: int = 0, active: bool | None = None, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    query = select(Indicator).order_by(Indicator.last_seen.desc())
    if active is not None:
        query = query.where(Indicator.is_active == active)
    return list(db.scalars(query.offset(offset).limit(min(limit, 200))).all())

@router.patch("/{indicator_id}", response_model=IndicatorOut)
def update_indicator(indicator_id: int, payload: IndicatorUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    indicator = db.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(404, "Indicador não encontrado")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(indicator, key, value)
    record_event(db, user, "indicator.updated", "indicator", indicator.id, {"fields": sorted(changes)}, request)
    db.commit()
    db.refresh(indicator)
    return indicator

@router.post("", response_model=IndicatorOut, status_code=status.HTTP_201_CREATED)
def create_indicator(payload: IndicatorCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    try:
        normalized = normalize_indicator(payload.value, payload.indicator_type)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    existing = db.scalar(select(Indicator).where(Indicator.value == normalized))
    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        existing.confidence = max(existing.confidence, payload.confidence)
        record_event(db, user, "indicator.observed", "indicator", existing.id, {"value": normalized}, request)
        db.commit()
        db.refresh(existing)
        return existing
    indicator = Indicator(**payload.model_dump(exclude={"value"}), value=normalized)
    db.add(indicator)
    db.flush()
    record_event(db, user, "indicator.created", "indicator", indicator.id, {"type": indicator.indicator_type, "tlp": indicator.tlp}, request)
    db.commit()
    db.refresh(indicator)
    return indicator
