def test_health_is_available_without_auth(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_login_returns_bearer_token(client):
    response = client.post("/api/v1/auth/token", data={"username": "admin@example.org", "password": "correct-horse-battery-2026"})
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["user"]["role"] == "admin"

def test_protected_route_requires_auth(client):
    response = client.get("/api/v1/assets")
    assert response.status_code == 401
