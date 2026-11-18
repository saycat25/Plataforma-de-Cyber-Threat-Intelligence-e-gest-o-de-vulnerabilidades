from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditEvent, User

def record_event(db: Session, actor: User | None, action: str, entity_type: str, entity_id: str | int | None, details: dict | None = None, request: Request | None = None) -> None:
    remote_addr = request.client.host if request and request.client else None
    db.add(AuditEvent(actor_id=actor.id if actor else None, action=action, entity_type=entity_type, entity_id=str(entity_id) if entity_id is not None else None, details=details or {}, remote_addr=remote_addr))
