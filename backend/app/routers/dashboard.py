from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.deps import get_current_user
from app.models import Asset, Case, Indicator, User, Vulnerability
from app.schemas import DashboardSummary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

@router.get("/summary", response_model=DashboardSummary)
def summary(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return DashboardSummary(
        assets_total=db.scalar(select(func.count(Asset.id))) or 0,
        vulnerabilities_open=db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.status.in_(["open", "in_progress"]))) or 0,
        vulnerabilities_critical=db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.priority == "critical", Vulnerability.status.in_(["open", "in_progress"]))) or 0,
        vulnerabilities_kev=db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.is_kev.is_(True), Vulnerability.status.in_(["open", "in_progress"]))) or 0,
        indicators_active=db.scalar(select(func.count(Indicator.id)).where(Indicator.is_active.is_(True))) or 0,
        cases_open=db.scalar(select(func.count(Case.id)).where(Case.status.not_in(["resolved", "closed"]))) or 0,
    )
