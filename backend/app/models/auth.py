"""Platform login accounts + RBAC. Deliberately separate from enterprise `identities`."""
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, Timestamps, UUIDPk

USER_STATUSES = ("pending", "active", "suspended", "disabled", "rejected")


class User(Base, UUIDPk, Timestamps):
    """A person who can log in to the IdentityOS admin portal."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','active','suspended','disabled','rejected')", name="status_valid"
        ),
        # case-insensitive uniqueness without needing the citext extension
        Index("uq_users_email_lower", text("lower(email)"), unique=True),
    )

    email: Mapped[str] = mapped_column(String(320), nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(nullable=True)
    status_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    roles: Mapped[list["Role"]] = relationship(
        secondary="user_roles", primaryjoin="User.id==UserRole.user_id",
        secondaryjoin="Role.id==UserRole.role_id", lazy="selectin", viewonly=True,
    )


class Role(Base, UUIDPk):
    __tablename__ = "roles"
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)  # slug, e.g. iam_admin
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, server_default="")
    is_system: Mapped[bool] = mapped_column(nullable=False, server_default="true")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)


class Permission(Base, UUIDPk):
    __tablename__ = "permissions"
    code: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)  # e.g. approvals:decide
    description: Mapped[str] = mapped_column(String(300), nullable=False, server_default="")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True
    )
    assigned_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    assigned_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_user_roles_role_id", "role_id"),)
