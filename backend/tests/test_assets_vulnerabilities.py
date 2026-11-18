def test_create_asset_and_vulnerability_calculates_priority(client, auth_headers):
    asset = client.post("/api/v1/assets", headers=auth_headers, json={"name": "ERP Produção", "environment": "production", "criticality": "critical", "internet_exposed": True})
    assert asset.status_code == 201
    asset_id = asset.json()["id"]
    vuln = client.post("/api/v1/vulnerabilities", headers=auth_headers, json={"cve_id": "CVE-2021-44228", "title": "Remote code execution vulnerability", "severity": "critical", "cvss_score": 10.0, "epss_score": 0.98, "is_kev": True, "asset_id": asset_id})
    assert vuln.status_code == 201
    assert vuln.json()["priority"] == "critical"
    assert vuln.json()["risk_score"] >= 99.0

def test_invalid_cve_is_rejected(client, auth_headers):
    response = client.post("/api/v1/vulnerabilities", headers=auth_headers, json={"cve_id": "NOT-A-CVE", "title": "Invalid CVE"})
    assert response.status_code == 422
