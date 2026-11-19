import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, Vulnerability
from app.services.risk import refresh_risk

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass
class ScannerFinding:
    cve_id: str
    title: str
    description: str | None
    severity: str
    cvss_score: float | None


def _severity(value: str | None) -> str:
    normalized = (value or "unknown").strip().lower()
    return normalized if normalized in {"unknown", "low", "medium", "high", "critical"} else "unknown"


def _score(value: object) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0 <= score <= 10 else None


def parse_trivy(report: dict) -> list[ScannerFinding]:
    findings: list[ScannerFinding] = []
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "artefato")[:180]
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            match = CVE_RE.fullmatch(str(item.get("VulnerabilityID") or "").strip())
            if not match:
                continue
            scores: list[float] = []
            cvss = item.get("CVSS") or {}
            if isinstance(cvss, dict):
                for provider in cvss.values():
                    if isinstance(provider, dict):
                        value = _score(provider.get("V3Score") or provider.get("V2Score") or provider.get("Score"))
                        if value is not None:
                            scores.append(value)
            cvss_score = max(scores) if scores else _score(item.get("CVSSScore"))
            package = str(item.get("PkgName") or "pacote desconhecido")[:120]
            installed = str(item.get("InstalledVersion") or "versão desconhecida")[:80]
            fixed = str(item.get("FixedVersion") or "não informado")[:80]
            title = str(item.get("Title") or f"{package}: {match.group(0)}")[:500]
            description = str(item.get("Description") or f"Alvo: {target}. Pacote: {package}. Versão instalada: {installed}. Versão corrigida: {fixed}.")[:12000]
            findings.append(ScannerFinding(match.group(0).upper(), title, description, _severity(item.get("Severity")), cvss_score))
    return findings


def parse_openvas_xml(report_xml: str) -> list[ScannerFinding]:
    if len(report_xml.encode("utf-8")) > 8_000_000:
        raise ValueError("Relatório OpenVAS excede o limite de 8 MB")
    upper = report_xml.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ValueError("Declarações DTD/ENTITY não são permitidas")
    try:
        root = ET.fromstring(report_xml)
    except ET.ParseError as exc:
        raise ValueError("XML OpenVAS inválido") from exc

    findings: list[ScannerFinding] = []
    for result in root.findall(".//result"):
        nvt = result.find("nvt")
        nvt = nvt if nvt is not None else result
        cve_text = nvt.findtext("cve") or ""
        name = result.findtext("name") or nvt.findtext("name") or "Achado OpenVAS"
        cve_ids = {match.upper() for match in CVE_RE.findall(cve_text + " " + name)}
        score = _score(result.findtext("severity"))
        if score is None:
            score = _score(nvt.findtext("cvss_base"))
        severity = _severity(nvt.findtext("severity"))
        if severity == "unknown" and score is not None:
            severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
        description = (result.findtext("description") or "Achado importado do relatório OpenVAS.")[:12000]
        for cve_id in sorted(cve_ids):
            findings.append(ScannerFinding(cve_id, name[:500], description, severity, score))
    return findings


def persist_findings(db: Session, asset: Asset, scanner: str, findings: list[ScannerFinding]) -> dict:
    created = 0
    updated = 0
    for finding in findings:
        existing = db.scalar(select(Vulnerability).where(
            Vulnerability.asset_id == asset.id,
            Vulnerability.cve_id == finding.cve_id,
        ))
        if existing is None:
            vulnerability = Vulnerability(
                cve_id=finding.cve_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                cvss_score=finding.cvss_score,
                source=scanner,
                asset=asset,
            )
            refresh_risk(vulnerability)
            db.add(vulnerability)
            created += 1
            continue
        if finding.cvss_score is not None and (existing.cvss_score is None or finding.cvss_score > existing.cvss_score):
            existing.cvss_score = finding.cvss_score
        if finding.severity != "unknown":
            existing.severity = finding.severity
        if finding.description:
            existing.description = finding.description
        if existing.source in {"trivy", "openvas"}:
            existing.source = scanner
        refresh_risk(existing)
        updated += 1
    db.flush()
    return {"findings_seen": len(findings), "created": created, "updated": updated, "ignored": 0}
