from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import FeedRun, Vulnerability
from app.services.risk import refresh_risk

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class FeedError(RuntimeError):
    pass

async def sync_cisa_kev(db: Session) -> dict:
    run = FeedRun(feed_name="cisa-kev", status="running")
    db.add(run)
    db.flush()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False) as client:
            response = await client.get(CISA_KEV_URL, headers={"Accept": "application/json", "User-Agent": "CTI-Platform/0.1 defensive-feed-sync"})
            response.raise_for_status()
            payload = response.json()
        entries = payload.get("vulnerabilities", [])
        created = 0
        for entry in entries:
            cve_id = entry.get("cveID")
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                continue
            existing = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id).order_by(Vulnerability.id).limit(1))
            title = str(entry.get("vulnerabilityName") or f"{cve_id} — CISA KEV")[:500]
            description = str(entry.get("shortDescription") or "")[:12000]
            if existing:
                existing.is_kev = True
                existing.description = description or existing.description
                refresh_risk(existing)
                continue
            vuln = Vulnerability(cve_id=cve_id, title=title, description=description, severity="unknown", is_kev=True, source="cisa-kev", status="open")
            refresh_risk(vuln)
            db.add(vuln)
            created += 1
        run.status = "success"
        run.items_seen = len(entries)
        run.items_created = created
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        return {"feed": "cisa-kev", "status": "success", "items_seen": len(entries), "items_created": created, "catalog_version": str(payload.get("catalogVersion", "unknown"))}
    except Exception as exc:
        db.rollback()
        run.status = "failed"
        run.error_message = str(exc)[:1000]
        run.finished_at = datetime.now(timezone.utc)
        db.add(run)
        db.commit()
        if isinstance(exc, httpx.HTTPError):
            raise FeedError("Não foi possível obter o feed CISA KEV") from exc
        raise FeedError("Falha ao processar o feed CISA KEV") from exc

async def sync_nvd_cve(db: Session, cve_id: str) -> dict:
    params = {"cveId": cve_id}
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0, connect=10.0), follow_redirects=False) as client:
            response = await client.get(NVD_CVE_URL, params=params, headers=headers, follow_redirects=False)
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise FeedError("Não foi possível consultar o NVD") from exc
    items = payload.get("vulnerabilities", [])
    if not items:
        raise FeedError("CVE não encontrado no NVD")
    cve = items[0].get("cve", {})
    metrics = cve.get("metrics", {})
    cvss = None
    severity = "unknown"
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key) or []
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss = cvss_data.get("baseScore")
            severity = str(cvss_data.get("baseSeverity") or "unknown").lower()
            break
    descriptions = cve.get("descriptions", [])
    description = next((item.get("value") for item in descriptions if item.get("lang") == "en"), None)
    published = cve.get("published")
    published_at = datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None
    existing = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id).order_by(Vulnerability.id).limit(1))
    if existing:
        existing.cvss_score = cvss
        existing.severity = severity if severity in {"low", "medium", "high", "critical"} else "unknown"
        existing.description = description or existing.description
        existing.published_at = published_at
        refresh_risk(existing)
        result = existing
        created = False
    else:
        result = Vulnerability(cve_id=cve_id, title=cve_id, description=description, cvss_score=cvss, severity=severity if severity in {"low", "medium", "high", "critical"} else "unknown", source="nvd", published_at=published_at, is_kev=False)
        refresh_risk(result)
        db.add(result)
        created = True
    db.commit()
    db.refresh(result)
    return {"created": created, "cve_id": result.cve_id, "cvss_score": result.cvss_score, "severity": result.severity, "risk_score": result.risk_score}
