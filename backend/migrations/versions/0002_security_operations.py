"""Authorized discovery, scanner intake, SIEM events and threat correlations."""
from alembic import op
from app.models import AuthorizedScope, SIEMEvent, ThreatCorrelation

revision = "0002_security_ops"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    AuthorizedScope.__table__.create(bind=bind, checkfirst=True)
    SIEMEvent.__table__.create(bind=bind, checkfirst=True)
    ThreatCorrelation.__table__.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    ThreatCorrelation.__table__.drop(bind=bind, checkfirst=True)
    SIEMEvent.__table__.drop(bind=bind, checkfirst=True)
    AuthorizedScope.__table__.drop(bind=bind, checkfirst=True)
