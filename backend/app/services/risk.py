from app.models import Asset, Vulnerability

CRITICALITY_POINTS = {"low": 1.0, "medium": 4.0, "high": 7.0, "critical": 10.0}

def calculate_risk(vulnerability: Vulnerability, asset: Asset | None) -> tuple[float, str]:
    """Deterministic contextual score (0-100); not a replacement for risk governance."""
    cvss_points = (vulnerability.cvss_score or 0.0) * 4.0
    kev_points = 25.0 if vulnerability.is_kev else 0.0
    epss_points = (vulnerability.epss_score or 0.0) * 15.0
    asset_points = CRITICALITY_POINTS.get(asset.criticality, 4.0) if asset else 0.0
    exposure_points = 10.0 if asset and asset.internet_exposed else 0.0
    score = round(min(100.0, cvss_points + kev_points + epss_points + asset_points + exposure_points), 2)
    priority = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    return score, priority

def refresh_risk(vulnerability: Vulnerability) -> None:
    vulnerability.risk_score, vulnerability.priority = calculate_risk(vulnerability, vulnerability.asset)
