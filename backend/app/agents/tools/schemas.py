"""Argument schemas for every tool. `extra="forbid"` everywhere: an argument the model invents is a schema error, not ignored.

Catalogue membership (is "Finance" a real department?) is checked by the gateway against the live directory, because the
catalogue is data, not code.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
PersonName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80, pattern=r"^[A-Za-z][A-Za-z .'-]*$")]


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# ─────────────────────────── read tools
class InspectUserAccess(Args):
    identity_id: uuid.UUID
    applications: list[Name] = Field(default_factory=list, max_length=10)
    entitlements: list[Name] = Field(default_factory=list, max_length=10)


class SearchIdentities(Args):
    query: Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=80)]
    limit: int = Field(5, ge=1, le=10)


class GetIdentityProfile(Args):
    identity_id: uuid.UUID


class GetDepartmentBaseline(Args):
    department: Name


class PeerAccessStats(Args):
    department: Name
    min_share: float = Field(0.5, gt=0.0, le=1.0)      # entitlements held by at least this share of the department


class ListPendingRequests(Args):
    limit: int = Field(10, ge=1, le=20)


# ─────────────────────────── write tools (proposals until the gateway commits them)
def _not_past(v: date | None) -> date | None:
    if v is not None and v < datetime.now(timezone.utc).date():
        raise ValueError("The effective date cannot be in the past")
    return v


class ProvisionUser(Args):
    first_name: PersonName
    last_name: PersonName
    email: EmailStr
    department: Name
    access_profile: Name
    start_date: date | None = None

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("start_date")
    @classmethod
    def _range(cls, v: date | None) -> date | None:
        today = datetime.now(timezone.utc).date()
        if v is not None and (v < today - timedelta(days=30) or v > today + timedelta(days=365)):
            raise ValueError("Start date must be within the last 30 days and the next 12 months")
        return v


class ModifyUserAccess(Args):
    identity_id: uuid.UUID
    change: Literal["mover", "access_request", "access_revocation"]
    to_department: Name | None = None
    access_profile: Name | None = None
    applications: list[Name] = Field(default_factory=list, max_length=10)
    entitlements: list[Name] = Field(default_factory=list, max_length=10)
    effective_date: date | None = None
    date_text: Annotated[str, StringConstraints(max_length=80)] | None = None
    justification: Annotated[str, StringConstraints(max_length=500)] = ""

    @field_validator("effective_date")
    @classmethod
    def _date(cls, v: date | None) -> date | None:
        return _not_past(v)


class DeprovisionUser(Args):
    identity_id: uuid.UUID
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=300)]
    effective_date: date | None = None

    @field_validator("effective_date")
    @classmethod
    def _date(cls, v: date | None) -> date | None:
        return _not_past(v)
