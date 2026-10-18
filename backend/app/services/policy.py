"""Deterministic policy engine for lifecycle requests (no model is involved, and nothing the requester writes
as a justification influences the outcome).

A request becomes a Plan: the entitlement lines it would add/remove, each with its own decision, and one overall
decision that is the strictest of its lines:

    DENY      a rule forbids it (separation of duties, leaver/terminated identity)        -> nothing is created
    CLARIFY   the request is not specific enough to evaluate                              -> nothing is created
    APPROVAL  allowed in principle but a human must decide (high/critical risk, outside   -> pending approval
              the department baseline, or the person is high-risk)
    AUTO      within policy                                                               -> approved by policy
    NOOP      nothing would change

Rules for an entitlement being ADDED (first match wins):
    already held                                         -> skipped
    would complete an active SoD policy                  -> DENY
    identity risk score >= stats.HIGH                    -> APPROVAL
    part of the target department's baseline, not critical -> AUTO
    low/medium risk and no `requires_approval` flag      -> AUTO
    anything else                                        -> APPROVAL
Removals (revocations, and entitlements a move leaves behind) are always AUTO.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import date

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (AccessProfile, AccessProfileEntitlement, Department, Entitlement, GovernancePolicy, Identity,
                        IdentityEntitlement)
from app.services import stats

AUTO, APPROVAL, DENY, CLARIFY, NOOP = "auto", "approval", "deny", "clarify", "noop"
_SEVERITY = {NOOP: 0, AUTO: 1, APPROVAL: 2, DENY: 3, CLARIFY: 4}
KINDS = ("mover", "access_request", "access_revocation")


@dataclass
class Line:
    entitlement_id: uuid.UUID
    name: str
    application: str
    risk_level: str
    action: str                 # add | remove
    decision: str
    reason: str


@dataclass
class Plan:
    kind: str
    identity: Identity
    from_dept: Department | None = None
    to_dept: Department | None = None
    effective_date: date | None = None
    lines: list[Line] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)          # informational (already held, ...)
    questions: list[str] = field(default_factory=list)      # what is needed to proceed (CLARIFY)
    decision: str = NOOP
    reasons: list[str] = field(default_factory=list)
    profile: AccessProfile | None = None                    # target access profile of a department move
    profile_options: list[AccessProfile] = field(default_factory=list)   # when the target department has several
    from_profile_name: str | None = None
    keeps: list[str] = field(default_factory=list)          # access the person keeps through a move

    @property
    def moves_department(self) -> bool:
        return self.kind == "mover" and self.to_dept is not None and (self.from_dept is None or self.from_dept.id != self.to_dept.id)

    @property
    def adds(self) -> list[Line]:
        return [l for l in self.lines if l.action == "add"]

    @property
    def removes(self) -> list[Line]:
        return [l for l in self.lines if l.action == "remove"]


async def _baseline(db: AsyncSession, dept_id: uuid.UUID | None) -> dict[uuid.UUID, Entitlement]:
    """Entitlements granted by any access profile of the department (its 'birthright' set)."""
    if not dept_id:
        return {}
    rows = (await db.execute(select(Entitlement).join(AccessProfileEntitlement, AccessProfileEntitlement.entitlement_id == Entitlement.id)
                             .join(AccessProfile, AccessProfile.id == AccessProfileEntitlement.access_profile_id)
                             .where(AccessProfile.department_id == dept_id))).scalars().all()
    return {e.id: e for e in rows}


async def _held(db: AsyncSession, identity_id: uuid.UUID) -> dict[uuid.UUID, Entitlement]:
    rows = (await db.execute(select(Entitlement).join(IdentityEntitlement, IdentityEntitlement.entitlement_id == Entitlement.id)
                             .where(IdentityEntitlement.identity_id == identity_id,
                                    IdentityEntitlement.status.in_(("active", "pending"))))).scalars().all()
    return {e.id: e for e in rows}


async def _sod_policies(db: AsyncSession) -> list[tuple[str, set[uuid.UUID]]]:
    rows = (await db.execute(select(GovernancePolicy).where(GovernancePolicy.policy_type == "sod", GovernancePolicy.is_active))).scalars().all()
    out = []
    for p in rows:
        try:
            out.append((p.name, {uuid.UUID(x) for x in p.rules.get("entitlements", [])}))
        except (ValueError, AttributeError):
            continue
    return out


async def _by_application(db: AsyncSession, app: str) -> list[Entitlement]:
    return list((await db.execute(select(Entitlement).where(func.lower(Entitlement.application) == app.lower())
                                  .order_by(Entitlement.name))).scalars().all())


async def _by_name(db: AsyncSession, name: str) -> Entitlement | None:
    return (await db.execute(select(Entitlement).where(func.lower(Entitlement.name) == name.lower()))).scalars().first()


def _line(e: Entitlement, action: str, decision: str, reason: str) -> Line:
    return Line(e.id, e.name, e.application, e.risk_level, action, decision, reason)


async def build_plan(db: AsyncSession, *, kind: str, identity: Identity, to_dept: Department | None = None,
                     applications: list[str] | None = None, roles: list[str] | None = None,
                     effective_date: date | None = None, date_text: str | None = None, access_profile: AccessProfile | None = None) -> Plan:
    assert kind in KINDS
    from_dept = await db.get(Department, identity.department_id) if identity.department_id else None
    plan = Plan(kind=kind, identity=identity, from_dept=from_dept, to_dept=to_dept, effective_date=effective_date)
    held = await _held(db, identity.id)

    # ---- hard stops and missing information
    if identity.lifecycle_state in ("leaver", "terminated") and kind != "access_revocation":
        plan.decision, plan.reasons = DENY, [f"{identity.full_name} is a {identity.lifecycle_state}; access cannot be added or moved."]
        return plan
    if date_text and not effective_date:
        plan.questions.append(f"“{date_text}” is not a fixed date. Which date should this take effect on?")
    if kind == "mover" and not to_dept:
        plan.questions.append("Which department should the person move to?")
    if kind == "mover" and to_dept and from_dept and to_dept.id == from_dept.id and not (applications or roles):
        plan.notes.append(f"{identity.full_name} is already in {to_dept.name}.")

    # the department whose baseline defines "normal" access for this request
    ref_dept = to_dept if kind == "mover" else from_dept
    baseline = await _baseline(db, ref_dept.id if ref_dept else None)

    # ---- a department move also provisions the new department's standard access (its access profile)
    profile_ents: list[Entitlement] = []
    if kind == "mover" and plan.moves_department and to_dept:
        if identity.access_profile_id:
            cur = await db.get(AccessProfile, identity.access_profile_id)
            plan.from_profile_name = cur.name if cur else None
        profs = list((await db.execute(select(AccessProfile).where(AccessProfile.department_id == to_dept.id).order_by(AccessProfile.name))).scalars())
        if access_profile:
            plan.profile = access_profile
        elif len(profs) == 1:
            plan.profile = profs[0]
        elif len(profs) > 1:
            plan.profile_options = profs
            plan.questions.append(f"{to_dept.name} has several access profiles ({', '.join(p.name for p in profs)}). Which one should {identity.full_name} get?")
        else:
            plan.notes.append(f"{to_dept.name} has no access profile defined, so no standard access is added.")
        if plan.profile:
            profile_ents = list((await db.execute(select(Entitlement).join(AccessProfileEntitlement, AccessProfileEntitlement.entitlement_id == Entitlement.id)
                                                   .where(AccessProfileEntitlement.access_profile_id == plan.profile.id).order_by(Entitlement.name))).scalars())

    # ---- resolve what was asked for to concrete entitlements
    wanted: list[Entitlement] = []
    for r in roles or []:
        e = await _by_name(db, r)
        if e:
            wanted.append(e)
        else:
            plan.questions.append(f"I don't know an entitlement called “{r}”.")
    for app in applications or []:
        ents = await _by_application(db, app)
        if not ents:
            plan.questions.append(f"“{app}” has no entitlements in this directory.")
            continue
        if kind == "access_revocation":
            wanted += [e for e in ents if e.id in held] or []
            if not any(e.id in held for e in ents):
                plan.notes.append(f"{identity.full_name} holds no {app} access.")
            continue
        in_base = [e for e in ents if e.id in baseline]
        if in_base:
            wanted += in_base
        elif len(ents) == 1:
            wanted += ents
        else:
            plan.questions.append(f"{app} has several entitlements ({', '.join(e.name for e in ents)}). Which one do you need?")
    if kind in ("access_request", "access_revocation") and not wanted and not plan.questions and not plan.notes:
        plan.questions.append("Which application or entitlement is this about?")
    wanted = list({e.id: e for e in profile_ents + wanted}.values())

    # ---- lines
    if kind == "access_revocation":
        plan.lines = [_line(e, "remove", AUTO, "Removing access always reduces risk.") for e in wanted if e.id in held]
        for e in wanted:
            if e.id not in held:
                plan.notes.append(f"{identity.full_name} does not hold {e.name}.")
    else:
        adds = [e for e in wanted if e.id not in held]
        for e in wanted:
            if e.id in held:
                plan.notes.append(f"{identity.full_name} already holds {e.name}.")
        removes: list[Entitlement] = []
        if kind == "mover" and plan.moves_department and from_dept:
            old = await _baseline(db, from_dept.id)
            removes = [held[i] for i in held if i in old and i not in baseline and i not in {a.id for a in adds}]
        resulting = (set(held) | {e.id for e in adds}) - {e.id for e in removes}
        sod = await _sod_policies(db)
        for e in adds:
            plan.lines.append(_add_decision(e, identity, baseline, ref_dept, sod, resulting, set(held)))
        for e in removes:
            plan.lines.append(_line(e, "remove", AUTO, f"Not part of the {to_dept.name} baseline, so it is removed with the move."))
        if kind == "mover" and plan.moves_department:
            gone = {e.id for e in removes}
            plan.keeps = sorted(e.name for i, e in held.items() if i not in gone)

    # ---- overall decision = strictest line
    lines_decision = max((l.decision for l in plan.lines), key=lambda d: _SEVERITY[d], default=NOOP)
    if plan.questions:
        plan.decision = CLARIFY
    elif plan.moves_department:
        plan.decision = max(AUTO, lines_decision, key=lambda d: _SEVERITY[d])
    else:
        plan.decision = lines_decision
    seen: list[str] = []
    for l in plan.lines:
        if l.decision in (DENY, APPROVAL) and l.reason not in seen:
            seen.append(l.reason)
    if plan.decision == AUTO:
        seen = ["Everything requested is within policy."] + [f"{l.name}: {l.reason}" for l in plan.adds[:6]]
    plan.reasons = seen
    return plan


def _add_decision(e: Entitlement, ident: Identity, baseline: dict, ref_dept: Department | None, sod: list, resulting: set, held_now: set) -> Line:
    for name, ents in sod:
        if e.id in ents and ents <= resulting and not ents <= held_now:
            return _line(e, "add", DENY, f"{e.name} would violate the separation-of-duties policy “{name}”.")
    if ident.risk_score >= stats.HIGH:
        return _line(e, "add", APPROVAL, f"{ident.full_name} has a high risk score ({ident.risk_score}/100), so a person must approve any new access.")
    if e.id in baseline and e.risk_level != "critical":
        return _line(e, "add", AUTO, f"{e.name} is part of the standard {ref_dept.name} access baseline.")
    if e.risk_level in ("low", "medium") and not e.requires_approval:
        return _line(e, "add", AUTO, f"{e.name} is {e.risk_level} risk and needs no approval.")
    why = []
    if e.risk_level in ("high", "critical"):
        why.append(f"{e.risk_level} risk")
    if e.requires_approval:
        why.append("flagged as requiring approval")
    if e.id not in baseline:
        why.append(f"not part of the standard {ref_dept.name} baseline" if ref_dept else "not part of a standard baseline")
    return _line(e, "add", APPROVAL, f"{e.name} is " + " and ".join(why) + ".")
