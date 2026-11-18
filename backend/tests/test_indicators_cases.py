def test_indicator_validation_and_normalization(client, auth_headers):
    response = client.post("/api/v1/indicators", headers=auth_headers, json={"value": "Example.COM.", "indicator_type": "domain", "confidence": 90, "tlp": "TLP:GREEN"})
    assert response.status_code == 201
    assert response.json()["value"] == "example.com"

def test_invalid_indicator_is_rejected(client, auth_headers):
    response = client.post("/api/v1/indicators", headers=auth_headers, json={"value": "999.999.999.999", "indicator_type": "ipv4"})
    assert response.status_code == 422

def test_create_case_and_audit_event(client, auth_headers):
    response = client.post("/api/v1/cases", headers=auth_headers, json={"title": "Suspected credential exposure", "description": "Investigar possível exposição de credenciais em repositório interno.", "severity": "high"})
    assert response.status_code == 201
    assert response.json()["case_number"].startswith("CTI-")
    events = client.get("/api/v1/audit/events", headers=auth_headers)
    assert events.status_code == 200
    assert any(event["action"] == "case.created" for event in events.json())
