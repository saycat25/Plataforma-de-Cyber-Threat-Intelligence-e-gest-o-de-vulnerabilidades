from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, verify_password
from app.models import User
from app.schemas import TokenOut, UserOut

router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/token", response_model=TokenOut)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> TokenOut:
    user = db.scalar(select(User).where(User.email == form_data.username.lower()))
    if user is None or not user.is_active or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="E-mail ou senha incorretos", headers={"WWW-Authenticate": "Bearer"})
    token = create_access_token(str(user.id), user.role)
    return TokenOut(access_token=token, expires_in=settings.access_token_expire_minutes * 60, user=UserOut.model_validate(user))
