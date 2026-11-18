from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.database import get_db
from app.deps import get_current_user, require_roles
from app.models import Asset, User, Vulnerability
from app.schemas import VulnerabilityCreate, VulnerabilityOut, VulnerabilityUpdate
from app.services.audit import record_event
from app.services.risk import refresh_risk

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerability management"])

@router.get("", response_model=list[VulnerabilityOut])
def list_vulnerabilities(limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0), priority: str | None = None, status_filter: str | None = Query(None, alias="status"), cve_id: str | None = None, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    query = select(Vulnerability).options(joinedload(Vulnerability.asset)).order_by(Vulnerability.risk_score.desc(), Vulnerability.created_at.desc())
    if priority:
        query = query.where(Vulnerability.priority == priority)
    if status_filter:
        query = query.where(Vulnerability.status == status_filter)
    if cve_id:
        query = query.where(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
    return list(db.scalars(query.offset(offset).limit(limit)).unique().all())

@router.post("", response_model=VulnerabilityOut, status_code=status.HTTP_201_CREATED)
def create_vulnerability(payload: VulnerabilityCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    asset = db.get(Asset, payload.asset_id) if payload.asset_id else None
    if payload.asset_id and asset is None:
        raise HTTPException(404, "Ativo associado não encontrado")
    vuln = Vulnerability(**payload.model_dump())
    vuln.asset = asset
    refresh_risk(vuln)
    db.add(vuln)
    db.flush()
    record_event(db, user, "vulnerability.created", "vulnerability", vuln.id, {"cve_id": vuln.cve_id, "priority": vuln.priority}, request)
    db.commit()
    db.refresh(vuln)
    return vuln

@router.patch("/{vulnerability_id}", response_model=VulnerabilityOut)
def update_vulnerability(vulnerability_id: int, payload: VulnerabilityUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    vuln = db.get(Vulnerability, vulnerability_id)
    if vuln is None:
        raise HTTPException(404, "Vulnerabilidade não encontrada")
    changes = payload.model_dump(exclude_unset=True)
    if "asset_id" in changes and changes["asset_id"] is not None:
        asset = db.get(Asset, changes["asset_id"])
        if asset is None:
            raise HTTPException(404, "Ativo associado não encontrado")
        vuln.asset = asset
        del changes["asset_id"]
    for key, value in changes.items():
        setattr(vuln, key, value)
    refresh_risk(vuln)
    record_event(db, user, "vulnerability.updated", "vulnerability", vuln.id, {"fields": sorted(changes)}, request)
    db.commit()
    db.refresh(vuln)
    return vuln
