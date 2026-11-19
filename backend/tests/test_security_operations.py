import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from app.core.config import settings


def create_asset(client, headers, ip_address="10.20.30.40"):
    response = client.post("/api/v1/assets", headers=headers, json={
        "name": "Servidor de aplicações",
        "ip_address": ip_address,
        "hostname": "app01.corp.example",
        "environment": "production",
        "criticality": "high",
    })
    assert response.status_code == 201
    return response.json()


def test_discovery_import_requires_active_authorized_scope(client, auth_headers):
    scope = client.post("/api/v1/discovery/scopes", headers=auth_headers, json={
        "scope_type": "cidr",
        "value": "10.20.30.0/24",
        "authorization_reference": "CHANGE-SEC-2026-010",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    })
    assert scope.status_code == 201
    imported = client.post("/api/v1/discovery/import", headers=auth_headers, json={
        "scope_id": scope.json()["id"],
        "source": "cmdb-export",
        "assets": [{"name": "app02", "ip_address": "10.20.30.41", "criticality": "high"}],
    })
    assert imported.status_code == 200
    assert imported.json()["assets_created"] == 1

    denied = client.post("/api/v1/discovery/import", headers=auth_headers, json={
        "scope_id": scope.json()["id"],
        "source": "untrusted-export",
        "assets": [{"name": "outside", "ip_address": "10.99.0.10"}],
    })
    assert denied.status_code == 403


def test_discovery_scope_creation_is_admin_only(client):
    login = client.post("/api/v1/auth/token", data={"username": "viewer@example.org", "password": "viewer-password-2026-strong"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    response = client.post("/api/v1/discovery/scopes", headers=headers, json={
        "scope_type": "domain",
        "value": "corp.example",
        "authorization_reference": "CHANGE-SEC-2026-011",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    })
    assert response.status_code == 403


def test_trivy_report_import_is_idempotent_per_asset_and_cve(client, auth_headers):
    asset = create_asset(client, auth_headers)
    payload = {
        "asset_id": asset["id"],
        "report": {"Results": [{"Target": "api-image", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-12345",
            "PkgName": "lib-example",
            "InstalledVersion": "1.0.0",
            "FixedVersion": "1.0.2",
            "Severity": "CRITICAL",
            "Title": "Example critical vulnerability",
            "Description": "Upgrade the affected package.",
            "CVSS": {"nvd": {"V3Score": 9.8}},
        }]}]},
    }
    first = client.post("/api/v1/scanners/trivy/import", headers=auth_headers, json=payload)
    assert first.status_code == 200
    assert first.json()["vulnerabilities_created"] == 1
    second = client.post("/api/v1/scanners/trivy/import", headers=auth_headers, json=payload)
    assert second.status_code == 200
    assert second.json()["vulnerabilities_created"] == 0
    assert second.json()["vulnerabilities_updated"] == 1


def test_openvas_xml_import_rejects_dtd_and_imports_cve(client, auth_headers):
    asset = create_asset(client, auth_headers, "10.20.30.42")
    xml = """<report><results><result><name>OpenSSL memory safety issue CVE-2023-12345</name>
      <host>10.20.30.42</host><severity>8.1</severity><description>Update the package.</description>
      <nvt><cve>CVE-2023-12345</cve><cvss_base>8.1</cvss_base></nvt>
      </result></results></report>"""
    response = client.post("/api/v1/scanners/openvas/import", headers=auth_headers, json={"asset_id": asset["id"], "report_xml": xml})
    assert response.status_code == 200
    assert response.json()["vulnerabilities_created"] == 1
    blocked = client.post("/api/v1/scanners/openvas/import", headers=auth_headers, json={
        "asset_id": asset["id"],
        "report_xml": "<!DOCTYPE report [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><report>&x;</report>",
    })
    assert blocked.status_code == 422


def test_siem_event_correlates_indicator_asset_and_open_vulnerability(client, auth_headers):
    asset = create_asset(client, auth_headers, "10.20.30.43")
    indicator = client.post("/api/v1/indicators", headers=auth_headers, json={
        "value": "203.0.113.77", "indicator_type": "ipv4", "confidence": 95, "tlp": "TLP:GREEN", "source": "test-feed",
    })
    assert indicator.status_code == 201
    vulnerability = client.post("/api/v1/vulnerabilities", headers=auth_headers, json={
        "cve_id": "CVE-2024-54321", "title": "Known vulnerable service", "severity": "high", "cvss_score": 8.2, "asset_id": asset["id"],
    })
    assert vulnerability.status_code == 201
    response = client.post("/api/v1/siem/events", headers=auth_headers, json={
        "source": "elastic-security",
        "external_id": "alert-0001",
        "event_type": "network.connection.suspicious",
        "severity": "high",
        "source_ip": "203.0.113.77",
        "destination_ip": "10.20.30.43",
        "indicator_values": [],
        "summary": "Conexão de origem sinalizada para investigação.",
        "raw_event": {"rule_id": "test-rule"},
    })
    assert response.status_code == 200
    assert response.json()["correlation_score"] >= 70
    assert response.json()["matched_indicator_ids"] == [indicator.json()["id"]]
    assert response.json()["matched_asset_ids"] == [asset["id"]]
    assert response.json()["matched_vulnerability_ids"] == [vulnerability.json()["id"]]
    listed = client.get("/api/v1/siem/correlations", headers=auth_headers)
    assert listed.status_code == 200
    assert listed.json()[0]["siem_event_id"] == response.json()["event"]["id"]


def test_siem_event_ingestion_is_idempotent(client, auth_headers):
    payload = {"source": "sentinel", "external_id": "same-alert", "event_type": "identity.alert", "severity": "medium", "summary": "Repeated event"}
    first = client.post("/api/v1/siem/events", headers=auth_headers, json=payload)
    second = client.post("/api/v1/siem/events", headers=auth_headers, json=payload)
    assert first.status_code == second.status_code == 200
    assert first.json()["event"]["id"] == second.json()["event"]["id"]
    assert second.json()["duplicate"] is True


def test_signed_cef_webhook_requires_valid_hmac(client, monkeypatch):
    secret = "test-webhook-secret-0123456789"
    monkeypatch.setattr(settings, "siem_webhook_secret", secret)
    body = "CEF:0|Acme|Gateway|1.0|AUTH-FAIL|Failed login|8|src=203.0.113.9 dst=10.20.30.44 msg=Repeated login failures"
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    response = client.post("/api/v1/siem/webhook", content=body, headers={"Content-Type": "application/cef", "X-CTI-Signature": f"sha256={signature}"})
    assert response.status_code == 200
    assert response.json()["event"]["source"] == "Acme:Gateway"
    denied = client.post("/api/v1/siem/webhook", content=body, headers={"Content-Type": "application/cef", "X-CTI-Signature": "sha256=invalid"})
    assert denied.status_code == 401


def test_deactivated_authorization_scope_cannot_import_assets(client, auth_headers):
    expired = client.post("/api/v1/discovery/scopes", headers=auth_headers, json={
        "scope_type": "domain",
        "value": "corp.example",
        "authorization_reference": "CHANGE-SEC-2026-099",
        "valid_until": (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat(),
    })
    assert expired.status_code == 201
    # Deactivation is the deterministic way to test a no-longer-authorized scope.
    scope_id = expired.json()["id"]
    deactivated = client.post(f"/api/v1/discovery/scopes/{scope_id}/deactivate", headers=auth_headers)
    assert deactivated.status_code == 200
    denied = client.post("/api/v1/discovery/import", headers=auth_headers, json={
        "scope_id": scope_id,
        "source": "cmdb",
        "assets": [{"name": "srv01", "hostname": "srv01.corp.example"}],
    })
    assert denied.status_code == 403


def test_domain_scope_accepts_subdomain_and_rejects_suffix_spoof(client, auth_headers):
    scope = client.post("/api/v1/discovery/scopes", headers=auth_headers, json={
        "scope_type": "domain",
        "value": "corp.example",
        "authorization_reference": "CHANGE-SEC-2026-100",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    })
    assert scope.status_code == 201
    allowed = client.post("/api/v1/discovery/import", headers=auth_headers, json={
        "scope_id": scope.json()["id"],
        "source": "cmdb",
        "assets": [{"name": "server", "hostname": "srv01.corp.example"}],
    })
    assert allowed.status_code == 200
    denied = client.post("/api/v1/discovery/import", headers=auth_headers, json={
        "scope_id": scope.json()["id"],
        "source": "cmdb",
        "assets": [{"name": "spoof", "hostname": "corp.example.attacker.invalid"}],
    })
    assert denied.status_code == 403


def test_siem_event_rejects_invalid_ip(client, auth_headers):
    response = client.post("/api/v1/siem/events", headers=auth_headers, json={
        "source": "test-siem", "external_id": "bad-ip", "event_type": "network.alert",
        "source_ip": "999.999.999.999", "summary": "Invalid network indicator",
    })
    assert response.status_code == 422


def test_discovery_import_deduplicates_repeated_identity_in_same_batch(client, auth_headers):
    scope = client.post("/api/v1/discovery/scopes", headers=auth_headers, json={
        "scope_type": "cidr", "value": "10.20.30.0/24",
        "authorization_reference": "CHANGE-SEC-2026-202",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    })
    assert scope.status_code == 201
    records = [
        {"name": "app01", "hostname": "app01.corp.example", "ip_address": "10.20.30.80"},
        {"name": "app01-renamed", "hostname": "app01.corp.example", "ip_address": "10.20.30.80"},
    ]
    imported = client.post("/api/v1/discovery/import", headers=auth_headers, json={
        "scope_id": scope.json()["id"], "source": "cmdb", "assets": records,
    })
    assert imported.status_code == 200
    assert imported.json()["assets_created"] == 1
    assert imported.json()["assets_updated"] == 1
    assets = client.get("/api/v1/assets", headers=auth_headers).json()
    assert len([asset for asset in assets if asset["ip_address"] == "10.20.30.80"]) == 1


def test_siem_correlation_links_events_with_shared_ip_in_previous_15_minutes(client, auth_headers):
    first = client.post("/api/v1/siem/events", headers=auth_headers, json={
        "source": "test-siem", "external_id": "campaign-001", "event_type": "auth.failure",
        "severity": "medium", "source_ip": "203.0.113.88", "summary": "Falhas de autenticação",
    })
    assert first.status_code == 200
    second = client.post("/api/v1/siem/events", headers=auth_headers, json={
        "source": "test-siem", "external_id": "campaign-002", "event_type": "auth.failure",
        "severity": "high", "source_ip": "203.0.113.88", "summary": "Nova sequência de falhas de autenticação",
    })
    assert second.status_code == 200
    assert second.json()["related_event_ids"] == [first.json()["event"]["id"]]
    assert second.json()["correlation_score"] >= 30
    correlations = client.get("/api/v1/siem/correlations", headers=auth_headers)
    assert correlations.status_code == 200
    assert correlations.json()[0]["related_event_ids"] == [first.json()["event"]["id"]]


def test_discovery_import_rejects_ip_and_hostname_matching_different_assets(client, auth_headers):
    first = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "Servidor A", "hostname": "server-a.corp.example", "ip_address": "10.20.30.91",
    })
    second = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "Servidor B", "hostname": "server-b.corp.example", "ip_address": "10.20.30.92",
    })
    assert first.status_code == second.status_code == 201
    scope = client.post("/api/v1/discovery/scopes", headers=auth_headers, json={
        "scope_type": "cidr", "value": "10.20.30.0/24",
        "authorization_reference": "CHANGE-SEC-2026-203",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    })
    assert scope.status_code == 201
    conflict = client.post("/api/v1/discovery/import", headers=auth_headers, json={
        "scope_id": scope.json()["id"], "source": "cmdb",
        "assets": [{"name": "Conflict", "hostname": "server-b.corp.example", "ip_address": "10.20.30.91"}],
    })
    assert conflict.status_code == 409


def test_siem_temporal_correlation_ignores_events_outside_15_minute_window(client, auth_headers):
    old_time = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()
    first = client.post("/api/v1/siem/events", headers=auth_headers, json={
        "source": "test-siem", "external_id": "old-campaign-event", "event_type": "auth.failure",
        "severity": "medium", "occurred_at": old_time, "source_ip": "203.0.113.89", "summary": "Evento antigo",
    })
    assert first.status_code == 200
    second = client.post("/api/v1/siem/events", headers=auth_headers, json={
        "source": "test-siem", "external_id": "new-campaign-event", "event_type": "auth.failure",
        "severity": "medium", "source_ip": "203.0.113.89", "summary": "Evento atual",
    })
    assert second.status_code == 200
    assert second.json()["related_event_ids"] == []
