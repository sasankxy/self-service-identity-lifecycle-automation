import uuid
from datetime import date, datetime

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Identity as SAIdentity, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk


class GovernancePolicy(Base, UUIDPk, Timestamps):
    __tablename__ = "governance_policies"
    __table_args__ = (
        CheckConstraint("severity IN ('low','medium','high','critical')", name="severity_valid"),
    )
    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    policy_type: Mapped[str] = mapped_column(String(40), nullable=False)  # sod, certification, access, ...
    description: Mapped[str] = mapped_column(String(1000), nullable=False, server_default="")
    rules: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    severity: Mapped[str] = mapped_column(String(10), nullable=False, server_default="medium")
    is_active: Mapped[bool] = mapped_column(nullable=False, server_default="true")
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class AuditLog(Base):
    """Append-only security/audit trail. Never stores passwords, tokens or hashes."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("severity IN ('info','low','medium','high','critical')", name="severity_valid"),
        CheckConstraint(
            "outcome IN ('success','failure','denied','flagged','pending','blocked')", name="outcome_valid"
        ),
        Index("ix_audit_logs_occurred_at", "occurred_at"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_category", "category"),
        Index("ix_audit_logs_actor", "actor_user_id"),
        Index("ix_audit_logs_target", "target_type", "target_id"),
    )
    id: Mapped[int] = mapped_column(BigInteger, SAIdentity(always=False), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(String(320), nullable=False, server_default="system")
    action: Mapped[str] = mapped_column(String(80), nullable=False)       # e.g. auth.login
    target_type: Mapped[str | None] = mapped_column(String(60))
    target_id: Mapped[str | None] = mapped_column(String(80))
    target_label: Mapped[str | None] = mapped_column(String(320))        # human-readable target
    category: Mapped[str] = mapped_column(String(30), nullable=False, server_default="system")
    severity: Mapped[str] = mapped_column(String(10), nullable=False, server_default="info")
    outcome: Mapped[str] = mapped_column(String(10), nullable=False, server_default="success")
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(300))
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class ComplianceFramework(Base, UUIDPk, Timestamps):
    __tablename__ = "compliance_frameworks"
    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, server_default="")
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class ComplianceControl(Base, UUIDPk):
    """A testable control. Framework compliance % = passing controls / total controls."""

    __tablename__ = "compliance_controls"
    __table_args__ = (
        CheckConstraint("status IN ('pass','fail','not_tested')", name="status_valid"),
        Index("uq_compliance_controls_code", "framework_id", "code", unique=True),
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False
    )
    code: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False, server_default="not_tested")
    last_tested_at: Mapped[datetime | None] = mapped_column()
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class CertificationCampaign(Base, UUIDPk, Timestamps):
    __tablename__ = "certification_campaigns"
    __table_args__ = (CheckConstraint("status IN ('active','completed','cancelled')", name="status_valid"),)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    scope_description: Mapped[str] = mapped_column(String(300), nullable=False, server_default="")
    due_date: Mapped[date] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False, server_default="active")
    completed_at: Mapped[datetime | None] = mapped_column()
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class CertificationItem(Base):
    """One identity under review in a campaign. Progress = decided items / total items."""

    __tablename__ = "certification_items"
    __table_args__ = (CheckConstraint("decision IN ('certified','revoked')", name="decision_valid"),)
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("certification_campaigns.id", ondelete="CASCADE"), primary_key=True
    )
    identity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), primary_key=True
    )
    decision: Mapped[str | None] = mapped_column(String(10))
    decided_at: Mapped[datetime | None] = mapped_column()


class GovernanceFinding(Base, UUIDPk):
    """One detected governance problem (orphaned account / privilege creep). A scan opens, refreshes and auto-resolves these;
    the unique key makes re-detection idempotent, and a dismissed finding stays dismissed while it is still detected."""

    __tablename__ = "governance_findings"
    __table_args__ = (
        CheckConstraint("kind IN ('orphan','creep')", name="kind_valid"),
        CheckConstraint("severity IN ('low','medium','high','critical')", name="severity_valid"),
        CheckConstraint("status IN ('open','resolved','dismissed')", name="status_valid"),
        UniqueConstraint("rule", "identity_id", "subject_key", name="uq_governance_findings_key"),
        Index("ix_governance_findings_status_kind", "status", "kind"),
        Index("ix_governance_findings_identity", "identity_id"),
    )
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    rule: Mapped[str] = mapped_column(String(40), nullable=False)
    identity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identities.id", ondelete="CASCADE"), nullable=False)
    subject_key: Mapped[str] = mapped_column(String(80), nullable=False, server_default="")   # e.g. the entitlement id for creep
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False, server_default="open")
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    source: Mapped[str] = mapped_column(String(20), nullable=False, server_default="scan")      # scan | scheduled | mover_trigger | ...
    first_detected_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    last_detected_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column()
    dismissed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    dismissed_reason: Mapped[str | None] = mapped_column(String(300))


class GovernanceScanRun(Base, UUIDPk):
    """History of full governance scans (scheduled, manual or CLI)."""

    __tablename__ = "governance_scan_runs"
    __table_args__ = (
        CheckConstraint("status IN ('ok','failed')", name="status_valid"),
        CheckConstraint("trigger IN ('scheduled','manual','cli')", name="trigger_valid"),
        Index("ix_governance_scan_runs_started_at", "started_at"),
    )
    started_at: Mapped[datetime] = mapped_column(nullable=False)
    finished_at: Mapped[datetime] = mapped_column(nullable=False)
    trigger: Mapped[str] = mapped_column(String(12), nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    identities_scanned: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    opened: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    resolved: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    open_total: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    applied_due: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error: Mapped[str | None] = mapped_column(String(500))
