import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.deps import get_current_user, require_roles
from app.models import Case, User
from app.schemas import CaseCreate, CaseOut, CaseUpdate
from app.services.audit import record_event

router = APIRouter(prefix="/cases", tags=["incident cases"])

@router.get("", response_model=list[CaseOut])
def list_cases(limit: int = 100, offset: int = 0, status_filter: str | None = None, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    query = select(Case).order_by(Case.created_at.desc())
    if status_filter:
        query = query.where(Case.status == status_filter)
    return list(db.scalars(query.offset(offset).limit(min(limit, 200))).all())

@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_case(payload: CaseCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    case = Case(case_number=f"CTI-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3).upper()}", **payload.model_dump())
    db.add(case)
    db.flush()
    record_event(db, user, "case.created", "case", case.id, {"case_number": case.case_number, "severity": case.severity}, request)
    db.commit()
    db.refresh(case)
    return case

@router.patch("/{case_id}", response_model=CaseOut)
def update_case(case_id: int, payload: CaseUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(404, "Caso não encontrado")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(case, key, value)
    record_event(db, user, "case.updated", "case", case.id, {"fields": sorted(changes)}, request)
    db.commit()
    db.refresh(case)
    return case
