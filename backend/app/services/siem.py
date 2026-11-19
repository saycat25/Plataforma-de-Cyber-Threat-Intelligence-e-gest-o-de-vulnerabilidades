import hashlib
import ipaddress
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, Indicator, SIEMEvent, ThreatCorrelation, Vulnerability
from app.schemas import SIEMEventIn

CEF_KEY_RE = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9]*)=")


def parse_cef(raw: str) -> SIEMEventIn:
    """Parse the CEF header and common extension fields without executing content."""
    if len(raw.encode("utf-8")) > 1_000_000:
        raise ValueError("Evento CEF excede o limite de 1 MB")
    parts = raw.strip().split("|", 7)
    if len(parts) != 8 or not parts[0].startswith("CEF:"):
        raise ValueError("Formato CEF inválido")
    version = parts[0][4:]
    if not version.isdigit():
        raise ValueError("Versão CEF inválida")
    vendor, product, device_version, signature_id, name, severity_raw, extension = parts[1:]
    fields: dict[str, str] = {}
    matches = list(CEF_KEY_RE.finditer(extension))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(extension)
        fields[match.group(1)] = extension[match.end():end].strip()
    try:
        severity_number = float(severity_raw)
    except ValueError:
        severity_number = 5.0
    severity = "critical" if severity_number >= 9 else "high" if severity_number >= 7 else "medium" if severity_number >= 4 else "low"
    source = f"{vendor}:{product}"[:80] or "cef"
    external_id = fields.get("externalId") or f"{signature_id}:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"
    source_ip = fields.get("src") or None
    destination_ip = fields.get("dst") or None
    indicators = [value for value in (source_ip, destination_ip) if value]
    summary = fields.get("msg") or name or "Evento CEF recebido"
    return SIEMEventIn(
        source=source,
        external_id=external_id[:200],
        event_type=f"CEF:{signature_id}"[:120],
        severity=severity,
        occurred_at=datetime.now(timezone.utc),
        source_ip=source_ip,
        destination_ip=destination_ip,
        indicator_values=indicators,
        summary=summary[:4000],
        raw_event={
            "format": "CEF",
            "version": version,
            "device_vendor": vendor[:120],
            "device_product": product[:120],
            "device_version": device_version[:80],
            "signature_id": signature_id[:120],
            "name": name[:300],
            "original_cef": raw.strip(),
        },
    )


def ingest_event(db: Session, payload: SIEMEventIn) -> tuple[SIEMEvent, ThreatCorrelation, bool]:
    existing = db.scalar(select(SIEMEvent).where(
        SIEMEvent.source == payload.source,
        SIEMEvent.external_id == payload.external_id,
    ))
    if existing:
        correlation = db.get(ThreatCorrelation, existing.id)
        if correlation is None:
            correlation = ThreatCorrelation(siem_event_id=existing.id, score=0, rationale=["Evento previamente recebido; correlação ainda não disponível."])
            db.add(correlation)
            db.flush()
        return existing, correlation, True

    ip_values = [value for value in (payload.source_ip, payload.destination_ip) if value]
    matched_assets = list(db.scalars(select(Asset).where(Asset.ip_address.in_(ip_values)).limit(50)).all()) if ip_values else []
    asset = matched_assets[0] if matched_assets else None
    asset_ids = [item.id for item in matched_assets]

    candidate_values: set[str] = set()
    for value in [*payload.indicator_values, *ip_values]:
        candidate = value.strip().lower()
        if not candidate:
            continue
        try:
            candidate = ipaddress.ip_address(candidate).compressed
        except ValueError:
            pass
        candidate_values.add(candidate)
    indicators = list(db.scalars(select(Indicator).where(
        Indicator.is_active.is_(True),
        Indicator.value.in_(candidate_values),
    )).all()) if candidate_values else []

    vulnerabilities = list(db.scalars(select(Vulnerability).where(
        Vulnerability.asset_id.in_(asset_ids),
        Vulnerability.status.in_(["open", "in_progress"]),
    ).order_by(Vulnerability.risk_score.desc()).limit(50)).all()) if asset_ids else []

    severity_base = {"low": 5, "medium": 15, "high": 25, "critical": 35}[payload.severity]
    score = severity_base
    rationale = [f"Severidade do evento: {payload.severity} (+{severity_base})."]
    if indicators:
        confidence_points = min(35, round(max(item.confidence for item in indicators) * 0.35))
        score += confidence_points
        rationale.append(f"{len(indicators)} indicador(es) ativo(s) correlacionado(s) (+{confidence_points}).")
    if matched_assets:
        score += 10
        asset_names = ", ".join(item.name for item in matched_assets[:5])
        rationale.append(f"Evento associado a {len(matched_assets)} ativo(s) inventariado(s): {asset_names} (+10).")
    if vulnerabilities:
        vulnerability_points = min(20, len(vulnerabilities) * 5)
        score += vulnerability_points
        rationale.append(f"{len(vulnerabilities)} vulnerabilidade(s) aberta(s) no ativo (+{vulnerability_points}).")
        if any(item.is_kev for item in vulnerabilities):
            score += 10
            rationale.append("Ativo possui vulnerabilidade listada no CISA KEV (+10).")
    score = min(100, score)
    if not indicators and not matched_assets and not vulnerabilities:
        rationale.append("Nenhum IOC ou ativo inventariado foi associado; correlação inconclusiva.")

    event = SIEMEvent(
        source=payload.source,
        external_id=payload.external_id,
        event_type=payload.event_type,
        severity=payload.severity,
        occurred_at=payload.occurred_at,
        asset_id=asset.id if asset else None,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        summary=payload.summary,
        raw_event=payload.raw_event,
    )
    db.add(event)
    db.flush()
    correlation = ThreatCorrelation(
        siem_event_id=event.id,
        score=score,
        matched_asset_ids=asset_ids,
        matched_indicator_ids=[item.id for item in indicators],
        matched_vulnerability_ids=[item.id for item in vulnerabilities],
        rationale=rationale,
    )
    db.add(correlation)
    db.flush()
    return event, correlation, False
