"""Enterprise identities being *managed* by IdentityOS (not portal login accounts)."""
import uuid
from datetime import date, datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk

CONNECTOR_STATUSES = ("demo", "not_configured", "disconnected", "connected")


class Department(Base, UUIDPk, Timestamps):
    __tablename__ = "departments"
    code: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    cost_center: Mapped[str | None] = mapped_column(String(40))
    parent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("departments.id", ondelete="SET NULL"))


class IdentityConnector(Base, UUIDPk, Timestamps):
    """Integration target (AD, Okta, AWS...). Status must be honest: seeded rows are never 'connected'."""

    __tablename__ = "identity_connectors"
    __table_args__ = (
        CheckConstraint(
            "status IN ('demo','not_configured','disconnected','connected')", name="status_valid"
        ),
    )
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    connector_type: Mapped[str] = mapped_column(String(60), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="not_configured")
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")  # never secrets
    last_sync_at: Mapped[datetime | None] = mapped_column(nullable=True)
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class AccessProfile(Base, UUIDPk, Timestamps):
    __tablename__ = "access_profiles"
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, server_default="")
    department_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("departments.id", ondelete="SET NULL"), index=True
    )
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class Entitlement(Base, UUIDPk, Timestamps):
    __tablename__ = "entitlements"
    __table_args__ = (
        UniqueConstraint("application", "name", name="uq_entitlements_application_name"),
        CheckConstraint("risk_level IN ('low','medium','high','critical')", name="risk_level_valid"),
    )
    application: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, server_default="")
    risk_level: Mapped[str] = mapped_column(String(10), nullable=False, server_default="low")
    requires_approval: Mapped[bool] = mapped_column(nullable=False, server_default="false")
    connector_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("identity_connectors.id", ondelete="SET NULL"), index=True
    )
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class AccessProfileEntitlement(Base):
    __tablename__ = "access_profile_entitlements"
    access_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("access_profiles.id", ondelete="CASCADE"), primary_key=True
    )
    entitlement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("entitlements.id", ondelete="CASCADE"), primary_key=True
    )


class Identity(Base, UUIDPk, Timestamps):
    __tablename__ = "identities"
    __table_args__ = (
        CheckConstraint(
            "lifecycle_state IN ('joiner','active','mover','leaver','terminated')",
            name="lifecycle_state_valid",
        ),
        CheckConstraint("identity_type IN ('employee','contractor','service')", name="type_valid"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        Index("uq_identities_email_lower", text("lower(email)"), unique=True),
        Index("ix_identities_lifecycle_state", "lifecycle_state"),
        Index("ix_identities_risk_score", "risk_score"),
    )
    employee_id: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    identity_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="employee")
    job_title: Mapped[str | None] = mapped_column(String(160))
    department_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("departments.id", ondelete="SET NULL"), index=True
    )
    manager_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("identities.id", ondelete="SET NULL"), index=True
    )
    access_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("access_profiles.id", ondelete="SET NULL"), index=True
    )
    lifecycle_state: Mapped[str] = mapped_column(String(20), nullable=False, server_default="joiner")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    start_date: Mapped[date | None] = mapped_column()
    end_date: Mapped[date | None] = mapped_column()
    last_authentication_at: Mapped[datetime | None] = mapped_column()
    is_demo: Mapped[bool] = mapped_column(nullable=False, server_default="false")


class IdentityEntitlement(Base, UUIDPk):
    __tablename__ = "identity_entitlements"
    __table_args__ = (
        UniqueConstraint("identity_id", "entitlement_id", name="uq_identity_entitlements_pair"),
        CheckConstraint("status IN ('active','revoked','pending','expired')", name="status_valid"),
    )
    identity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entitlement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("entitlements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    granted_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    granted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    expires_at: Mapped[datetime | None] = mapped_column()
    source: Mapped[str] = mapped_column(String(30), nullable=False, server_default="manual")
