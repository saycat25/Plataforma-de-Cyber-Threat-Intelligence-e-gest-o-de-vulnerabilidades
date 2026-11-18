from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.deps import require_roles
from app.models import AuditEvent, User

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("/events")
def list_audit_events(limit: int = 100, offset: int = 0, db: Session = Depends(get_db), _: User = Depends(require_roles("admin"))):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).offset(offset).limit(min(limit, 200))).all()
    return [{"id": e.id, "actor_id": e.actor_id, "action": e.action, "entity_type": e.entity_type, "entity_id": e.entity_id, "details": e.details, "remote_addr": e.remote_addr, "created_at": e.created_at} for e in events]
