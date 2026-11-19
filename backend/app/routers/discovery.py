import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.deps import get_current_user, require_roles
from app.models import Asset, AuthorizedScope, User
from app.schemas import AuthorizedScopeCreate, AuthorizedScopeOut, DiscoveryImportOut, DiscoveryImportRequest
from app.services.audit import record_event
from app.services.discovery import normalize_scope, record_matches_scope, scope_is_current

router = APIRouter(prefix="/discovery", tags=["authorized asset discovery"])


@router.get("/scopes", response_model=list[AuthorizedScopeOut])
def list_scopes(db: Session = Depends(get_db), _: User = Depends(require_roles("admin", "analyst"))):
    return list(db.scalars(select(AuthorizedScope).order_by(AuthorizedScope.created_at.desc())).all())


@router.post("/scopes", response_model=AuthorizedScopeOut, status_code=status.HTTP_201_CREATED)
def create_scope(payload: AuthorizedScopeCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    try:
        value = normalize_scope(payload.scope_type, payload.value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    valid_until = payload.valid_until
    if valid_until.tzinfo is None:
        valid_until = valid_until.replace(tzinfo=timezone.utc)
    if valid_until <= datetime.now(timezone.utc):
        raise HTTPException(422, "A autorização precisa possuir validade futura")
    existing = db.scalar(select(AuthorizedScope).where(
        AuthorizedScope.scope_type == payload.scope_type,
        AuthorizedScope.value == value,
    ))
    if existing:
        raise HTTPException(409, "Já existe um escopo com esse tipo e valor")
    scope = AuthorizedScope(
        scope_type=payload.scope_type,
        value=value,
        authorization_reference=payload.authorization_reference.strip(),
        valid_until=valid_until,
        created_by=user.id,
    )
    db.add(scope)
    db.flush()
    record_event(db, user, "discovery.scope_created", "authorized_scope", scope.id, {"scope_type": scope.scope_type, "value": scope.value, "authorization_reference": scope.authorization_reference}, request)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Escopo já cadastrado") from exc
    db.refresh(scope)
    return scope


@router.post("/scopes/{scope_id}/deactivate", response_model=AuthorizedScopeOut)
def deactivate_scope(scope_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    scope = db.get(AuthorizedScope, scope_id)
    if scope is None:
        raise HTTPException(404, "Escopo autorizado não encontrado")
    scope.is_active = False
    record_event(db, user, "discovery.scope_deactivated", "authorized_scope", scope.id, {"value": scope.value}, request)
    db.commit()
    db.refresh(scope)
    return scope


@router.post("/import", response_model=DiscoveryImportOut)
def import_discovered_assets(payload: DiscoveryImportRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    scope = db.get(AuthorizedScope, payload.scope_id)
    if scope is None or not scope_is_current(scope):
        raise HTTPException(403, "Escopo inexistente, expirado ou desativado")
    for record in payload.assets:
        if not record.hostname and not record.ip_address:
            raise HTTPException(422, "Cada registro precisa informar hostname ou endereço IP")
        if record.hostname:
            try:
                record.hostname = normalize_scope("hostname", record.hostname)
            except ValueError as exc:
                raise HTTPException(422, "Hostname inválido no inventário importado") from exc
        if record.ip_address:
            try:
                record.ip_address = ipaddress.ip_address(record.ip_address).compressed
            except ValueError as exc:
                raise HTTPException(422, "Endereço IP inválido no inventário importado") from exc
        if not record_matches_scope(scope, record.hostname, record.ip_address):
            raise HTTPException(403, "Importação bloqueada: um ou mais registros estão fora do escopo autorizado")

    created = 0
    updated = 0
    for record in payload.assets:
        conditions = []
        if record.ip_address:
            conditions.append(Asset.ip_address == record.ip_address)
        if record.hostname:
            conditions.append(Asset.hostname == record.hostname.strip().lower())
        existing = db.scalar(select(Asset).where(or_(*conditions)).limit(1)) if conditions else None
        if existing is None:
            asset = Asset(**record.model_dump())
            asset.hostname = record.hostname.strip().lower() if record.hostname else None
            asset.tags = [f"discovery:{payload.source}"]
            db.add(asset)
            created += 1
            continue
        existing.name = record.name
        existing.hostname = record.hostname.strip().lower() if record.hostname else existing.hostname
        existing.ip_address = record.ip_address or existing.ip_address
        existing.environment = record.environment
        existing.criticality = record.criticality
        existing.owner = record.owner or existing.owner
        existing.internet_exposed = record.internet_exposed
        tag = f"discovery:{payload.source}"
        existing.tags = list(dict.fromkeys([*(existing.tags or []), tag]))
        updated += 1

    record_event(db, user, "discovery.assets_imported", "authorized_scope", scope.id, {"source": payload.source, "records_seen": len(payload.assets), "created": created, "updated": updated}, request)
    db.commit()
    return DiscoveryImportOut(scope_id=scope.id, records_seen=len(payload.assets), assets_created=created, assets_updated=updated, source=payload.source)
