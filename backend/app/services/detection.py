"""Proactive governance detection: orphaned accounts and privilege creep.

Read-only and deterministic. `detect()` returns Detection objects; storing them as findings is governance_scan's job.

ORPHANED ACCOUNTS (kind="orphan") - an account that no longer has a legitimate, accountable owner or purpose:
    leaver_with_access    terminated identity that still holds access (critical); leaver past its end date still holding access (high)
    expired_still_active  end date has passed but the identity is still live and holds access (e.g. expired contractor)        (high)
    dormant_account       no sign-in for DORMANT_DAYS (or never signed in since start) while holding access          (medium; high if it holds high/critical access)
    no_owner              service account without an owner, or contractor without a sponsor                                   (medium)
    manager_departed      the identity's manager is a leaver/terminated, so nobody is accountable for its access               (medium)

PRIVILEGE CREEP (kind="creep") - access beyond what the person's role baseline justifies:
    excess_access         a held entitlement that is not in the baseline of the person's access profile / department
                          and was not granted through an approved request (source "request:*"). Severity = the entitlement's risk level.
    The baseline is the same "birthright" map the policy engine uses (access profiles of the department, plus the person's own profile).
    Approved exceptions are not flagged: the approval is their justification. Service identities and identities with no department
    or profile have no baseline, so they are not judged.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (AccessProfile, AccessProfileEntitlement, Department, Entitlement, Identity, IdentityEntitlement)

DORMANT_DAYS = 90
NEVER_SIGNED_IN_GRACE_DAYS = 30
LIVE_STATES = ("joiner", "active", "mover")
RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
RULES = {
    "orphan": ("leaver_with_access", "expired_still_active", "dormant_account", "no_owner", "manager_departed"),
    "creep": ("excess_access",),
}


@dataclass(frozen=True)
class Detection:
    kind: str
    rule: str
    identity_id: uuid.UUID
    subject_key: str
    severity: str
    title: str
    details: dict = field(default_factory=dict, compare=False, hash=False)

    @property
    def key(self) -> tuple[str, uuid.UUID, str]:
        return (self.rule, self.identity_id, self.subject_key)


def _names(ents: list[Entitlement], limit: int = 8) -> list[str]:
    out = sorted(e.name for e in ents)
    return out if len(out) <= limit else out[:limit] + [f"+{len(out) - limit} more"]


def _worst(ents: list[Entitlement]) -> str:
    return max((e.risk_level for e in ents), key=lambda r: RANK.get(r, 0), default="low")


def orphan_detections(ident: Identity, held: list[Entitlement], manager: Identity | None, *, today: date, now: datetime) -> list[Detection]:
    out: list[Detection] = []
    state, who = ident.lifecycle_state, ident.full_name

    def add(rule: str, severity: str, title: str, **details) -> None:
        out.append(Detection("orphan", rule, ident.id, "", severity, title, {"state": state, **details}))

    if state == "terminated" and held:
        add("leaver_with_access", "critical", f"{who} is terminated but still holds {len(held)} entitlement(s)",
            entitlements=_names(held), count=len(held))
    elif state == "leaver" and held and ident.end_date and ident.end_date < today:
        add("leaver_with_access", "high", f"{who} left on {ident.end_date.isoformat()} but still holds {len(held)} entitlement(s)",
            entitlements=_names(held), count=len(held), end_date=ident.end_date.isoformat(), days_overdue=(today - ident.end_date).days)
    if state in LIVE_STATES and held and ident.end_date and ident.end_date < today:
        add("expired_still_active", "high", f"{who}'s end date ({ident.end_date.isoformat()}) has passed but the account is still active",
            end_date=ident.end_date.isoformat(), days_overdue=(today - ident.end_date).days, entitlements=_names(held), count=len(held))
    if state in ("active", "mover") and held:
        last = ident.last_authentication_at
        severity = "high" if _worst(held) in ("high", "critical") else "medium"
        if last is not None and last < now - timedelta(days=DORMANT_DAYS):
            add("dormant_account", severity, f"{who} has not signed in for {(now - last).days} days but holds {len(held)} entitlement(s)",
                last_authentication_at=last.isoformat(), days_inactive=(now - last).days, count=len(held))
        elif last is None and ident.start_date and ident.start_date < today - timedelta(days=NEVER_SIGNED_IN_GRACE_DAYS):
            add("dormant_account", severity, f"{who} has never signed in (started {ident.start_date.isoformat()}) but holds {len(held)} entitlement(s)",
                last_authentication_at=None, never_signed_in=True, count=len(held))
    if state in LIVE_STATES and ident.manager_id is None:
        if ident.identity_type == "service":
            add("no_owner", "medium", f"Service account {who} has no owner", identity_type="service")
        elif ident.identity_type == "contractor":
            add("no_owner", "medium", f"Contractor {who} has no sponsor", identity_type="contractor")
    if state in LIVE_STATES and manager is not None and manager.lifecycle_state in ("leaver", "terminated"):
        add("manager_departed", "medium", f"{who}'s manager {manager.full_name} is {manager.lifecycle_state}",
            manager=manager.full_name, manager_state=manager.lifecycle_state)
    return out


def creep_detections(ident: Identity, held_rows: list[tuple[Entitlement, IdentityEntitlement]], baseline: set[uuid.UUID],
                     dept: Department | None, profile: AccessProfile | None) -> list[Detection]:
    if ident.identity_type == "service" or ident.lifecycle_state in ("leaver", "terminated"):
        return []
    if not (ident.department_id or ident.access_profile_id):
        return []
    where = dept.name if dept else (profile.name if profile else "its")
    out = []
    for ent, grant in held_rows:
        if ent.id in baseline or (grant.source or "").startswith("request:"):
            continue
        out.append(Detection("creep", "excess_access", ident.id, str(ent.id), ent.risk_level,
                             f"{ent.name} ({ent.application}) is outside the {where} access baseline",
                             {"entitlement": ent.name, "application": ent.application, "risk_level": ent.risk_level, "source": grant.source,
                              "department": dept.name if dept else None, "access_profile": profile.name if profile else None,
                              "granted_at": grant.granted_at.isoformat() if grant.granted_at else None}))
    return out


async def detect(db: AsyncSession, *, identity_ids: set[uuid.UUID] | None = None, now: datetime | None = None) -> tuple[list[Detection], int]:
    """All detections for every identity (or only `identity_ids`). Returns (detections, identities scanned)."""
    now = now or datetime.now(timezone.utc)
    today = now.date()
    q = select(Identity)
    if identity_ids is not None:
        if not identity_ids:
            return [], 0
        q = q.where(Identity.id.in_(identity_ids))
    idents = list((await db.execute(q)).scalars())

    ents = {e.id: e for e in (await db.execute(select(Entitlement))).scalars()}
    depts = {d.id: d for d in (await db.execute(select(Department))).scalars()}
    profiles = {p.id: p for p in (await db.execute(select(AccessProfile))).scalars()}
    prof_ents: dict[uuid.UUID, set[uuid.UUID]] = {}
    for pid, eid in (await db.execute(select(AccessProfileEntitlement.access_profile_id, AccessProfileEntitlement.entitlement_id))).all():
        prof_ents.setdefault(pid, set()).add(eid)
    dept_profiles: dict[uuid.UUID, list[uuid.UUID]] = {}
    for p in profiles.values():
        if p.department_id:
            dept_profiles.setdefault(p.department_id, []).append(p.id)

    gq = select(IdentityEntitlement).where(IdentityEntitlement.status.in_(("active", "pending")))
    if identity_ids is not None:
        gq = gq.where(IdentityEntitlement.identity_id.in_(identity_ids))
    grants: dict[uuid.UUID, list[IdentityEntitlement]] = {}
    for g in (await db.execute(gq)).scalars():
        grants.setdefault(g.identity_id, []).append(g)

    manager_ids = {i.manager_id for i in idents if i.manager_id}
    managers = {m.id: m for m in (await db.execute(select(Identity).where(Identity.id.in_(manager_ids)))).scalars()} if manager_ids else {}

    found: list[Detection] = []
    for ident in idents:
        rows = [(ents[g.entitlement_id], g) for g in grants.get(ident.id, []) if g.entitlement_id in ents]
        held = [e for e, _ in rows]
        found += orphan_detections(ident, held, managers.get(ident.manager_id), today=today, now=now)
        baseline = set(prof_ents.get(ident.access_profile_id, set()))
        for pid in dept_profiles.get(ident.department_id, []):
            baseline |= prof_ents.get(pid, set())
        found += creep_detections(ident, rows, baseline, depts.get(ident.department_id), profiles.get(ident.access_profile_id))
    return found, len(idents)
