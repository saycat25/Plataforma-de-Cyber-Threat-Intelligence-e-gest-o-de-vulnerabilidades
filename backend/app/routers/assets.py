from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.deps import get_current_user, require_roles
from app.models import Asset, User
from app.schemas import AssetCreate, AssetOut, AssetUpdate
from app.services.audit import record_event

router = APIRouter(prefix="/assets", tags=["assets"])

@router.get("", response_model=list[AssetOut])
def list_assets(limit: int = 100, offset: int = 0, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return list(db.scalars(select(Asset).order_by(Asset.created_at.desc()).offset(offset).limit(min(limit, 200))).all())

@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(payload: AssetCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.flush()
    record_event(db, user, "asset.created", "asset", asset.id, {"name": asset.name}, request)
    db.commit()
    db.refresh(asset)
    return asset

@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Ativo não encontrado")
    return asset

@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: int, payload: AssetUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Ativo não encontrado")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(asset, key, value)
    record_event(db, user, "asset.updated", "asset", asset.id, {"fields": sorted(changes)}, request)
    db.commit()
    db.refresh(asset)
    return asset

@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Ativo não encontrado")
    record_event(db, user, "asset.deleted", "asset", asset.id, {"name": asset.name}, request)
    db.delete(asset)
    db.commit()
