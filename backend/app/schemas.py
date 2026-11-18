from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=14, max_length=128)
    role: Literal["admin", "analyst", "viewer"] = "viewer"

class UserOut(ORMModel):
    id: int
    email: EmailStr
    role: str
    is_active: bool

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut

class AssetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=180)
    hostname: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=64)
    environment: Literal["production", "staging", "development", "test", "cloud", "on-prem"] = "production"
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    owner: str | None = Field(default=None, max_length=180)
    internet_exposed: bool = False
    tags: list[str] = Field(default_factory=list, max_length=30)
    notes: str | None = Field(default=None, max_length=4000)

class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=180)
    hostname: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=64)
    environment: Literal["production", "staging", "development", "test", "cloud", "on-prem"] | None = None
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    owner: str | None = Field(default=None, max_length=180)
    internet_exposed: bool | None = None
    tags: list[str] | None = Field(default=None, max_length=30)
    notes: str | None = Field(default=None, max_length=4000)

class AssetOut(ORMModel):
    id: int
    name: str
    hostname: str | None
    ip_address: str | None
    environment: str
    criticality: str
    owner: str | None
    internet_exposed: bool
    tags: list[str]
    notes: str | None
    created_at: datetime
    updated_at: datetime

class VulnerabilityCreate(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=30)
    title: str = Field(min_length=2, max_length=500)
    description: str | None = Field(default=None, max_length=12000)
    severity: Literal["unknown", "low", "medium", "high", "critical"] = "unknown"
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    epss_score: float | None = Field(default=None, ge=0, le=1)
    is_kev: bool = False
    status: Literal["open", "in_progress", "mitigated", "accepted", "false_positive", "closed"] = "open"
    source: str = Field(default="manual", max_length=80)
    asset_id: int | None = None
    published_at: datetime | None = None

class VulnerabilityUpdate(BaseModel):
    status: Literal["open", "in_progress", "mitigated", "accepted", "false_positive", "closed"] | None = None
    asset_id: int | None = None
    epss_score: float | None = Field(default=None, ge=0, le=1)
    is_kev: bool | None = None

class VulnerabilityOut(ORMModel):
    id: int
    cve_id: str
    title: str
    description: str | None
    severity: str
    cvss_score: float | None
    epss_score: float | None
    is_kev: bool
    status: str
    priority: str
    risk_score: float
    source: str
    asset_id: int | None
    published_at: datetime | None
    created_at: datetime

class IndicatorCreate(BaseModel):
    value: str = Field(min_length=3, max_length=512)
    indicator_type: Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]
    confidence: int = Field(default=50, ge=0, le=100)
    tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"] = "TLP:CLEAR"
    source: str = Field(default="manual", max_length=180)
    description: str | None = Field(default=None, max_length=4000)

class IndicatorUpdate(BaseModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"] | None = None
    is_active: bool | None = None

class IndicatorOut(ORMModel):
    id: int
    value: str
    indicator_type: str
    confidence: int
    tlp: str
    source: str
    description: str | None
    is_active: bool
    first_seen: datetime
    last_seen: datetime

class CaseCreate(BaseModel):
    title: str = Field(min_length=4, max_length=240)
    description: str = Field(min_length=10, max_length=12000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    assignee: EmailStr | None = None
    source: str = Field(default="manual", max_length=80)

class CaseUpdate(BaseModel):
    status: Literal["open", "triage", "investigating", "contained", "resolved", "closed"] | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    assignee: EmailStr | None = None
    resolution: str | None = Field(default=None, max_length=12000)

class CaseOut(ORMModel):
    id: int
    case_number: str
    title: str
    description: str
    severity: str
    status: str
    assignee: str | None
    source: str
    resolution: str | None
    created_at: datetime
    updated_at: datetime

class AnalysisRequest(BaseModel):
    question: str = Field(min_length=10, max_length=4000)
    vulnerability_ids: list[int] = Field(default_factory=list, max_length=20)
    indicator_ids: list[int] = Field(default_factory=list, max_length=20)

class AnalysisOut(BaseModel):
    model: str
    analysis: str
    disclaimer: str = "Análise assistiva; valide as evidências e decisões com um analista responsável."

class FeedSyncOut(BaseModel):
    feed: str
    status: str
    items_seen: int
    items_created: int
    catalog_version: str | None = None

class DashboardSummary(BaseModel):
    assets_total: int
    vulnerabilities_open: int
    vulnerabilities_critical: int
    vulnerabilities_kev: int
    indicators_active: int
    cases_open: int
