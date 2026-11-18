from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import hash_password
from app.deps import require_roles
from app.models import User
from app.schemas import UserCreate, UserOut
from app.services.audit import record_event

router = APIRouter(prefix="/users", tags=["user administration"])

@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_roles("admin"))):
    return list(db.scalars(select(User).order_by(User.email)).all())

@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_roles("admin"))):
    email = str(payload.email).lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Já existe um usuário com este e-mail")
    user = User(email=email, password_hash=hash_password(payload.password), role=payload.role, is_active=True)
    db.add(user)
    db.flush()
    record_event(db, actor, "user.created", "user", user.id, {"email": email, "role": user.role}, request)
    db.commit()
    db.refresh(user)
    return user
