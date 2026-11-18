from types import SimpleNamespace

from app.services.risk import calculate_risk

def test_kev_and_exposed_critical_asset_raise_risk():
    vuln = SimpleNamespace(cvss_score=9.8, is_kev=True, epss_score=0.95)
    asset = SimpleNamespace(criticality="critical", internet_exposed=True)
    score, priority = calculate_risk(vuln, asset)
    assert score == 98.45
    assert priority == "critical"

def test_low_signal_vulnerability_is_low_priority():
    vuln = SimpleNamespace(cvss_score=1.0, is_kev=False, epss_score=0.01)
    score, priority = calculate_risk(vuln, None)
    assert score < 35
    assert priority == "low"
