import uuid
from datetime import date, datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, Sequence, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk


class LifecycleRequest(Base, UUIDPk, Timestamps):
    __tablename__ = "lifecycle_requests"
    __table_args__ = (
        CheckConstraint("request_type IN ('joiner','mover','leaver','privilege')", name="type_valid"),
        CheckConstraint(
            "status IN ('draft','pending_approval','approved','rejected','provisioning','completed','failed','cancelled')",
            name="status_valid",
        ),
        Index("ix_lifecycle_requests_status", "status"),
        Index("ix_lifecycle_requests_type_created", "request_type", "created_at"),
    )
    identity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    request_type: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending_approval")
    from_department_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("departments.id", ondelete="SET NULL")
    )
    to_department_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("departments.id", ondelete="SET NULL")
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    effective_date: Mapped[date | None] = mapped_column()
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    completed_at: Mapped[datetime | None] = mapped_column()
    ref_no: Mapped[int] = mapped_column(
        Integer, Sequence("lifecycle_request_ref_seq", start=5000), unique=True, nullable=False,
        server_default=text("nextval('lifecycle_request_ref_seq')"),
    )
    requester_name: Mapped[str | None] = mapped_column(String(160))   # business requester, e.g. "HR Operations"
    justification: Mapped[str | None] = mapped_column(Text)
    duration_hours: Mapped[int | None] = mapped_column(Integer)         # time-boxed privilege grants
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class LifecycleRequestEntitlement(Base):
    """Entitlements a request adds or removes (the 'entitlement delta')."""

    __tablename__ = "lifecycle_request_entitlements"
    __table_args__ = (CheckConstraint("action IN ('add','remove')", name="action_valid"),)
    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("lifecycle_requests.id", ondelete="CASCADE"), primary_key=True
    )
    entitlement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("entitlements.id", ondelete="CASCADE"), primary_key=True
    )
    action: Mapped[str] = mapped_column(String(6), primary_key=True)


class RiskAssessment(Base, UUIDPk):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint("score BETWEEN 0 AND 100", name="score_range"),
        CheckConstraint("level IN ('low','medium','high','critical')", name="level_valid"),
        Index("ix_risk_assessments_identity_assessed", "identity_id", "assessed_at"),
    )
    identity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    lifecycle_request_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("lifecycle_requests.id", ondelete="SET NULL"), index=True
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[str] = mapped_column(String(10), nullable=False)
    triggers: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")
    assessed_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class ApprovalRequest(Base, UUIDPk):
    __tablename__ = "approval_requests"
    __table_args__ = (
        CheckConstraint("status IN ('pending','approved','rejected','expired')", name="status_valid"),
        CheckConstraint("priority IN ('normal','urgent')", name="priority_valid"),
        Index("ix_approval_requests_status_requested", "status", "requested_at"),
    )
    lifecycle_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("lifecycle_requests.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entitlement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("entitlements.id", ondelete="SET NULL")
    )
    risk_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("risk_assessments.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(10), nullable=False, server_default="pending")
    priority: Mapped[str] = mapped_column(String(10), nullable=False, server_default="normal")
    requested_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None] = mapped_column()
    decision_comment: Mapped[str | None] = mapped_column(Text)
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")
