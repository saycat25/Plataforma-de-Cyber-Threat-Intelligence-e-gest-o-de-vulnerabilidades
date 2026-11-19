from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

class User(TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="viewer", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

class Asset(TimestampMixin, Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(180), index=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    environment: Mapped[str] = mapped_column(String(40), default="production", nullable=False)
    criticality: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    owner: Mapped[str | None] = mapped_column(String(180), nullable=True)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="asset")

class Vulnerability(TimestampMixin, Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (Index("ix_vulnerability_cve_status", "cve_id", "status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    priority: Mapped[str] = mapped_column(String(20), default="low", nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    source: Mapped[str] = mapped_column(String(80), default="manual", nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    asset: Mapped[Asset | None] = relationship(back_populates="vulnerabilities")

class Indicator(TimestampMixin, Base):
    __tablename__ = "indicators"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(String(512), unique=True, index=True, nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    tlp: Mapped[str] = mapped_column(String(12), default="TLP:CLEAR", nullable=False)
    source: Mapped[str] = mapped_column(String(180), default="manual", nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class Case(TimestampMixin, Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_number: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(320), nullable=True)
    source: Mapped[str] = mapped_column(String(80), default="manual", nullable=False)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(80), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    remote_addr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)

class FeedRun(Base):
    __tablename__ = "feed_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    feed_name: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    items_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    items_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthorizedScope(TimestampMixin, Base):
    """Explicitly approved network/domain scope for passive asset imports."""
    __tablename__ = "authorized_scopes"
    __table_args__ = (UniqueConstraint("scope_type", "value", name="uq_authorized_scope_type_value"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    authorization_reference: Mapped[str] = mapped_column(String(240), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class SIEMEvent(Base):
    __tablename__ = "siem_events"
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_siem_source_external_id"),
        Index("ix_siem_event_source_ip_time", "source_ip", "occurred_at"),
        Index("ix_siem_event_destination_ip_time", "destination_ip", "occurred_at"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    raw_event: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ThreatCorrelation(Base):
    __tablename__ = "threat_correlations"
    siem_event_id: Mapped[int] = mapped_column(ForeignKey("siem_events.id", ondelete="CASCADE"), primary_key=True)
    score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    related_event_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    matched_asset_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    matched_indicator_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    matched_vulnerability_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    rationale: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
