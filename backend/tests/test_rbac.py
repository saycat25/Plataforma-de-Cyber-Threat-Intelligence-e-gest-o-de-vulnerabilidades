def test_viewer_can_read_but_cannot_create_assets(client):
    response = client.post("/api/v1/auth/token", data={"username": "viewer@example.org", "password": "viewer-password-2026-strong"})
    assert response.status_code == 200
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/api/v1/assets", headers=headers).status_code == 200
    denied = client.post("/api/v1/assets", headers=headers, json={"name": "Restricted asset"})
    assert denied.status_code == 403
