import sys

from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models import User

def main() -> int:
    email = settings.bootstrap_admin_email
    password = settings.bootstrap_admin_password
    if not email or not password:
        print("Bootstrap ignorado: configure BOOTSTRAP_ADMIN_EMAIL e BOOTSTRAP_ADMIN_PASSWORD.")
        return 0
    if len(password) < 14:
        print("A senha de bootstrap deve ter ao menos 14 caracteres.", file=sys.stderr)
        return 2
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == email.lower()))
        if existing:
            print("Administrador já existe; nenhuma alteração realizada.")
            return 0
        db.add(User(email=email.lower(), password_hash=hash_password(password), role="admin", is_active=True))
        db.commit()
    print(f"Administrador criado: {email.lower()}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
