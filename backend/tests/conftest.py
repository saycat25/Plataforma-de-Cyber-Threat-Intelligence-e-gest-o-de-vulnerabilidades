import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-0123456789-0123456789")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import hash_password
from app.main import app
from app.models import User

@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    with TestingSession() as db:
        db.add(User(email="admin@example.org", password_hash=hash_password("correct-horse-battery-2026"), role="admin", is_active=True))
        db.add(User(email="viewer@example.org", password_hash=hash_password("viewer-password-2026-strong"), role="viewer", is_active=True))
        db.commit()
    def override_get_db():
        with TestingSession() as db:
            yield db
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()

@pytest.fixture()
def auth_headers(client):
    response = client.post("/api/v1/auth/token", data={"username": "admin@example.org", "password": "correct-horse-battery-2026"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
