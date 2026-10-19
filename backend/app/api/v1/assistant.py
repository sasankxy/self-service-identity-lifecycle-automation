"""Directory assistant: understands lifecycle requests, checks them against policy, and (after an explicit confirm) submits them.

It is NOT a generative model. Answers come from persisted data; changes only happen through POST /assistant/execute,
which re-evaluates the policy on the server and never trusts what the browser says the decision was.

Understanding is two-layered:
  1. the standalone NLU pipeline (app.services.nlu -> backend/nlu) parses lifecycle requests such as
     "Move Rahul Sharma from Engineering to Finance" or "What access does Kai Chen have to Salesforce?"
     into intent + slots, which are then answered with read-only lookups;
  2. anything the NLU does not anchor to a person (analytics questions like "show pending approvals",
     bare names, "high-risk identities") goes to the original keyword rules, unchanged.
If the NLU cannot be loaded the assistant silently degrades to layer 2 only.
"""
import re
from datetime import date

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import csrf
from app.core.deps import get_db, require_permission
from app.core.errors import ApiError
from app.models import (AccessProfile, ApprovalRequest, Department, Entitlement, Identity, IdentityEntitlement, LifecycleRequest,
                        LifecycleRequestEntitlement)
from copy import deepcopy

from app.services import lifecycle, memory, namematch, nlu, policy, scope, slm, stats
from app.services.cache import invalidate
from app.services.accounts import Principal

router = APIRouter(prefix="/assistant", tags=["assistant"], dependencies=[Depends(csrf.csrf_protect)])
STOP = set("""the and for with show list who what which are any all has have how many does about from that this please give tell find lookup look
risk score scores high low medium flagged anomalies anomaly pending approval approvals approve identity identities account accounts access
onboard onboarding hire offboard offboarding revoke leave leaver leavers joiner joiners mover movers status check inspect review report
user users employee employees""".split())


class QueryIn(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    session_id: str | None = Field(None, max_length=64)      # one per chat window; enables follow-up answers and pronouns
    input_mode: Literal["text", "voice"] = "text"            # "voice": the text came from speech recognition, so names may be misheard


def _kv(items): return {"type": "kv", "items": [[k, "—" if v is None else str(v)] for k, v in items]}
def _text(t): return {"type": "text", "text": t}
def _list(items): return {"type": "list", "items": items}
def _head(t): return {"type": "heading", "text": t}


async def _identity_card(db: AsyncSession, i: Identity) -> list[dict]:
    dept = await db.get(Department, i.department_id) if i.department_id else None
    prof = await db.get(AccessProfile, i.access_profile_id) if i.access_profile_id else None
    n_active = (await db.execute(select(func.count()).select_from(IdentityEntitlement).where(
        IdentityEntitlement.identity_id == i.id, IdentityEntitlement.status.in_(("active", "pending"))))).scalar_one()
    reqs = (await db.execute(select(LifecycleRequest.ref_no, LifecycleRequest.request_type, LifecycleRequest.status).where(
        LifecycleRequest.identity_id == i.id).order_by(LifecycleRequest.created_at.desc()).limit(3))).all()
    return [_head(i.full_name), _kv([
        ("Email", i.email), ("Department", dept.name if dept else None), ("Access profile", prof.name if prof else None),
        ("Lifecycle state", i.lifecycle_state), ("Risk score", f"{i.risk_score} / 100 ({stats.risk_level(i.risk_score)})"),
        ("Current entitlements", n_active), ("Recent requests", ", ".join(f"REQ-{n} {t} ({s})" for n, t, s in reqs) or "none")])]


async def _legacy(db: AsyncSession, actor: Principal, query: str) -> tuple[list[dict], bool]:
    """Original keyword router (unchanged behaviour)."""
    low = query.lower()
    blocks: list[dict] = []
    handled = True
    words = [w for w in re.findall(r"[a-z0-9.@'_-]+", low) if len(w) >= 3 and w not in STOP]

    # 1. a specific identity?
    matches: list[Identity] = []
    if words:
        conds = [or_(func.lower(Identity.full_name).like(f"%{w}%"), func.lower(Identity.email).like(f"%{w}%")) for w in words]
        cand = (await db.execute(select(Identity).where(or_(*conds)).limit(60))).scalars().all()
        scored = [(sum(w in (c.full_name + " " + c.email).lower() for w in words), c) for c in cand]
        best = max((s for s, _ in scored), default=0)
        matches = [c for s, c in scored if s == best and best > 0]
        # Without any access-management vocabulary, only treat the text as a name lookup if every word is a WHOLE word of the
        # person's name/e-mail ("Kai Chen", "kai.chen"). Substring matching made "how are you" answer with the Youngs.
        if matches and not scope.in_scope(query):
            parts = [x for w in words for x in re.findall(r"[a-z0-9]+", w)]
            matches = [c for c in matches if len(parts) <= 3 and all(x in set(re.findall(r"[a-z0-9]+", (c.full_name + " " + c.email).lower())) for x in parts)]
    if 1 <= len(matches) <= 3:
        for i in matches:
            blocks += await _identity_card(db, i)
    elif len(matches) > 3:
        blocks += [_text(f"{len(matches)} identities match. Be more specific; the first few are:"), _list([f"{m.full_name} <{m.email}>" for m in matches[:6]])]
    # 2. intents
    elif any(k in low for k in ("pending", "approval", "approve")):
        rows = (await db.execute(select(LifecycleRequest.ref_no, LifecycleRequest.request_type, Identity.full_name, ApprovalRequest.priority)
                                 .join(ApprovalRequest, ApprovalRequest.lifecycle_request_id == LifecycleRequest.id)
                                 .join(Identity, Identity.id == LifecycleRequest.identity_id).where(ApprovalRequest.status == "pending")
                                 .order_by(ApprovalRequest.requested_at.desc()).limit(6))).all()
        total = (await db.execute(select(func.count()).select_from(ApprovalRequest).where(ApprovalRequest.status == "pending"))).scalar_one()
        blocks += [_head(f"{total} approval(s) pending"), _list([f"REQ-{n} · {t} · {name}" + (" · URGENT" if p == "urgent" else "") for n, t, name, p in rows] or ["Nothing pending."])]
        blocks.append({"type": "action", "label": "Open approvals queue", "action": "nav:approvals"})
    elif any(k in low for k in ("risk", "flagged", "anomal", "high")):
        total, items = await stats.flagged_identities(db, 5, 0)
        blocks += [_head(f"{total} identities at or above risk score {stats.HIGH}"),
                   _list([f"{i['name']} · {i['risk_score']}/100 · " + ("; ".join(i["triggers"]) or "no trigger recorded") for i in items] or ["None."])]
        blocks.append({"type": "action", "label": "Open risk analytics", "action": "nav:risk"})
    elif any(k in low for k in ("onboard", "hire", "joiner")):
        blocks.append(_text("I can't create identities from chat. Use the onboarding form; it creates a Joiner request and routes it for approval."))
        if actor.can("identities:write"):
            blocks.append({"type": "action", "label": "Open onboarding form", "action": "open-onboard"})
    elif any(k in low for k in ("offboard", "revoke", "leave", "terminate")):
        rows = (await db.execute(select(LifecycleRequest.ref_no, Identity.full_name, LifecycleRequest.status)
                                 .join(Identity, Identity.id == LifecycleRequest.identity_id)
                                 .where(LifecycleRequest.request_type == "leaver", LifecycleRequest.status.in_(("pending_approval", "approved")))
                                 .order_by(LifecycleRequest.created_at.desc()).limit(6))).all()
        blocks += [_text("Deprovisioning is executed through approved Leaver requests; I can't revoke access from chat."),
                   _head("Open Leaver requests"), _list([f"REQ-{n} · {name} · {s}" for n, name, s in rows] or ["None."])]
    else:
        handled = False
        blocks += [_text("I can look things up in the directory. Try: an employee's name or email, “high-risk identities”, or “pending approvals”.")]
    return blocks, handled


# ───────────────────────────── NLU-driven answers ─────────────────────────────
LABELS = {"JOINER": "Onboard (joiner)", "MOVER": "Department move (mover)", "LEAVER": "Offboard (leaver)",
          "ACCESS_REQUEST": "Access request", "ACCESS_REVOCATION": "Access revocation", "ACCESS_STATUS_QUERY": "Access status question"}
KIND = {"MOVER": "mover", "ACCESS_REQUEST": "access_request", "ACCESS_REVOCATION": "access_revocation", "LEAVER": "leaver"}
DECISION_TITLE = {policy.AUTO: "Policy decision: within policy, no approval needed", policy.APPROVAL: "Policy decision: needs a human approval",
                  policy.DENY: "Policy decision: blocked", policy.CLARIFY: "I need a bit more information", policy.NOOP: "Nothing to change"}


def _understood(res: dict, actor: Principal) -> dict:
    s, rows = res["slots"], [("Understood as", LABELS[res["intent"]["label"]])]
    who = s.get("person") or s.get("employee_id") or ("you (" + actor.email + ")" if s.get("subject_reference") == "SELF" else None)
    rows += [("Person", who), ("From department", s.get("source_department")),
             ("To department" if res["intent"]["label"] == "MOVER" else "Department", s.get("target_department") or s.get("department")),
             ("Applications", ", ".join(s.get("applications") or []) or None), ("Entitlements", ", ".join(s.get("access_roles") or []) or None)]
    d = s.get("effective_date")
    if d:
        rows.append(("Effective date", d["value"] if d.get("resolved") else f"{d['expression']} (not a fixed date)"))
    rows.append(("Reason", s.get("reason")))
    return _kv([(k, v) for k, v in rows if v])


async def _resolve_identities(db: AsyncSession, actor: Principal, s: dict) -> list[Identity]:
    if s.get("employee_id"):
        cond = func.lower(Identity.employee_id) == s["employee_id"].lower()
    elif s.get("person"):
        parts = [p for p in re.findall(r"[a-z0-9.'-]+", s["person"].lower()) if len(p) >= 2]
        if not parts:
            return []
        cond = func.coalesce(func.lower(Identity.full_name), "").like(f"%{parts[0]}%")
        for p in parts:   # every name part must appear in the name or e-mail
            cond = cond & or_(func.lower(Identity.full_name).like(f"%{p}%"), func.lower(Identity.email).like(f"%{p}%"))
    elif s.get("subject_reference") == "SELF":
        cond = func.lower(Identity.email) == actor.email.lower()
    else:
        return []
    return list((await db.execute(select(Identity).where(cond).order_by(Identity.full_name).limit(25))).scalars().all())


async def _entitlements(db: AsyncSession, identity_id, apps: list[str] | None = None, roles: list[str] | None = None) -> list[str]:
    q = (select(Entitlement.application, Entitlement.name, Entitlement.risk_level, IdentityEntitlement.status)
         .join(IdentityEntitlement, IdentityEntitlement.entitlement_id == Entitlement.id)
         .where(IdentityEntitlement.identity_id == identity_id, IdentityEntitlement.status.in_(("active", "pending"))))
    if apps or roles:
        q = q.where(or_(func.lower(Entitlement.application).in_([a.lower() for a in apps or []]),
                        func.lower(Entitlement.name).in_([r.lower() for r in roles or []])))
    rows = (await db.execute(q.order_by(Entitlement.application, Entitlement.name))).all()
    lines = [f"{n} ({a}) · {r} risk" + (" · pending" if st == "pending" else "") for a, n, r, st in rows]
    return lines if len(lines) <= 12 else lines[:12] + [f"…and {len(lines) - 12} more"]


async def _dept_by_name(db: AsyncSession, name: str | None) -> Department | None:
    return (await db.execute(select(Department).where(func.lower(Department.name) == name.lower()))).scalar_one_or_none() if name else None


# ---- proposal: what the browser sends back on "Confirm". The SERVER rebuilds the plan from it; the decision is never trusted.
class Proposal(BaseModel):
    kind: Literal["mover", "access_request", "access_revocation", "leaver"]
    identity_id: uuid.UUID
    to_department: str | None = Field(None, max_length=120)
    access_profile: str | None = Field(None, max_length=120)
    applications: list[str] = Field(default_factory=list, max_length=10)
    roles: list[str] = Field(default_factory=list, max_length=10)
    effective_date: date | None = None
    date_text: str | None = Field(None, max_length=80)
    text: str = Field("", max_length=500)


async def _plan_from(db: AsyncSession, p: Proposal, actor: Principal) -> policy.Plan:
    ident = await db.get(Identity, p.identity_id)
    if not ident:
        raise ApiError(404, "not_found", "Identity not found.")
    to_dept = await _dept_by_name(db, p.to_department) if p.to_department else None
    if p.to_department and not to_dept:
        raise ApiError(422, "validation_error", "Unknown department.", fields={"to_department": "Unknown department"})
    prof = None
    if p.access_profile:
        prof = (await db.execute(select(AccessProfile).where(AccessProfile.department_id == (to_dept.id if to_dept else None),
                                                             func.lower(AccessProfile.name) == p.access_profile.lower()))).scalar_one_or_none()
        if not prof:
            raise ApiError(422, "validation_error", "Unknown access profile for that department.", fields={"access_profile": "Unknown access profile"})
    return await policy.build_plan(db, kind=p.kind, identity=ident, to_dept=to_dept, applications=p.applications, roles=p.roles,
                                   effective_date=p.effective_date, date_text=p.date_text, access_profile=prof,
                                   requester_id=uuid.UUID(actor.id))


def _plan_blocks(plan: policy.Plan, actor: Principal, proposal: Proposal) -> list[dict]:
    blocks = [_head(DECISION_TITLE[plan.decision])]
    if plan.questions:
        blocks.append(_list(plan.questions))
    if plan.reasons and plan.decision != policy.CLARIFY:
        blocks.append(_list(plan.reasons))
    rows = []
    if plan.kind == "leaver" and plan.decision != policy.NOOP:
        rows.append(("Offboarding", "Deactivates the account and revokes all access"))
    if plan.moves_department:
        rows.append(("Department", f"{plan.from_dept.name if plan.from_dept else '—'} → {plan.to_dept.name}"))
    if plan.profile and plan.moves_department:
        rows.append(("Access profile", f"{plan.from_profile_name or '—'} → {plan.profile.name}"))
    if plan.adds:
        rows.append(("Add access", ", ".join(f"{l.name} ({l.risk_level})" for l in plan.adds)))
    if plan.removes:
        rows.append(("Remove access", ", ".join(l.name for l in plan.removes)))
    if plan.keeps:
        rows.append(("Keeps", ", ".join(plan.keeps)))
    if rows:
        rows.append(("Takes effect", plan.effective_date.isoformat() if plan.effective_date else "immediately"))
        blocks.append(_kv(rows))
    blocks += [_text(n) for n in plan.notes]
    for pr in plan.profile_options:       # one click re-plans with that profile; it never submits anything
        blocks.append({"type": "action", "label": f"Use profile: {pr.name}", "action": "replan",
                       "proposal": {**proposal.model_dump(mode="json"), "access_profile": pr.name}})
    if plan.decision in (policy.AUTO, policy.APPROVAL):
        if actor.can("identities:write"):
            label = ("Confirm and apply" if plan.decision == policy.AUTO else "Submit for approval")
            if plan.decision == policy.AUTO and plan.effective_date and plan.effective_date > date.today():
                label = f"Confirm (scheduled for {plan.effective_date.isoformat()})"
            blocks.append({"type": "action", "label": label, "action": "execute", "expected_decision": plan.decision,
                           "proposal": proposal.model_dump(mode="json")})
        else:
            blocks.append(_text("Your role can review this but not submit it."))
    return blocks


async def _slm_blocks(request: Request, query: str) -> list[dict]:
    """Suggestions from the local SLM. Suggest-only: the output is catalogue-validated and offered as a clickable rephrasing."""
    client = slm.get_client(request.app.state.settings)
    out = await client.interpret(query, nlu.catalogue()) if client and scope.in_scope(query) else None
    if not out:
        return []
    rows = [("Intent", LABELS.get(out["intent"], "unclear")), ("Person", out["person"]), ("From department", out["source_department"]),
            ("To department", out["target_department"]), ("Applications", ", ".join(out["applications"]) or None)]
    blocks = [_text("I couldn't pin this down with my rules, so a local language model took a look. It can only suggest; it can't "
                    "grant or change anything. Please check:"), _kv([(k, v) for k, v in rows if v])]
    if out["question"]:
        blocks.append(_text(out["question"]))
    if out["rephrase"]:
        blocks.append({"type": "action", "label": f"Use: “{out['rephrase']}”", "action": f"prompt:{out['rephrase']}"})
    return blocks


async def _voice_name_suggestions(db: AsyncSession, heard: str) -> list[dict]:
    """Closest directory names to a (possibly misheard) spoken name. Same visibility as the exact lookup: any identity the caller can read."""
    rows = (await db.execute(select(Identity.employee_id, Identity.full_name, Identity.email).limit(5000))).all()
    return namematch.rank(heard, [tuple(r) for r in rows])


def _suggestion_blocks(heard: str, found: list[dict], ctx: dict, label: str, slots: dict) -> list[dict]:
    """Reuses the 'which one do you mean?' machinery: the reply (a click, a name, or 'the second one') fills the person slot."""
    ctx["pending"] = {"label": label, "slots": slots, "ask": "person", "question": "Which one do you mean? (name, employee ID or email)",
                      "options": [{"value": f["employee_id"], "label": f["full_name"], "employee_id": f["employee_id"],
                                   "aliases": [f["employee_id"], f["email"], f["email"].split("@")[0]]} for f in found]}
    names = [f["full_name"] for f in found]
    blocks = [_text(f"I couldn't find “{heard}”. Voice input can mishear names. Did you mean one of these?"),
              _list([f"{f['full_name']} <{f['email']}> · {f['employee_id']}" for f in found])]
    for f in found:      # a button sends the name (or the employee ID if two suggestions share a name)
        send = f["full_name"] if names.count(f["full_name"]) == 1 else f["employee_id"]
        blocks.append({"type": "action", "label": f["full_name"] if send == f["full_name"] else f"{f['full_name']} · {f['employee_id']}",
                       "action": f"send:{send}"})
    return blocks + [_text("Or say “cancel” to drop this request.")]


async def _answer_nlu(db: AsyncSession, actor: Principal, res: dict, request: Request, query: str, ctx: dict | None = None,
                      voice: bool = False) -> tuple[list[dict], bool]:
    """`ctx` is filled with what the conversation memory should keep: ctx['pending'] (the question just asked) and ctx['person']."""
    ctx = ctx if ctx is not None else {}
    label, s = res["intent"]["label"], res["slots"]
    slm_used = False
    # echo the interpretation for actions and clarifications; a plain status lookup just answers
    blocks: list[dict] = [] if label == "ACCESS_STATUS_QUERY" and res["status"] == "PARSED" else [_understood(res, actor)]

    if res["status"] == "NEEDS_CLARIFICATION":       # blocking ambiguity or a missing required field: ask, don't guess
        blocks += [_text("I need a little more detail before I can look this up:"), _list(res["clarification_questions"] or
                   [f"Please provide: {', '.join(res['missing_fields'])}."])]
        ctx["pending"] = _pending_for(label, s, res["missing_fields"], res["clarification_questions"])
        if label in ("JOINER", "MOVER") and not s.get("target_department") and not res.get("unresolved"):
            extra = await _slm_blocks(request, query)
            blocks, slm_used = blocks + extra, bool(extra)
        return blocks, slm_used

    for k, v in (res.get("unresolved") or {}).items():       # names the NLU saw but could not map to the directory
        blocks.append(_text(f"I didn't recognise {k.replace('_', ' ')}: {', '.join(v) if isinstance(v, list) else v}."))

    matches = await _resolve_identities(db, actor, s)

    if label == "JOINER":
        if any(m.full_name.lower() == (s.get("person") or "").lower() for m in matches):
            blocks.append(_text(f"{s['person']} already exists in the directory, so this isn't a new joiner."))
            return blocks + await _identity_card(db, matches[0]), False
        blocks.append(_text("New identities are created with the onboarding form (it needs an e-mail address and access profile); "
                            "it creates a Joiner request and routes it for approval."))
        if not s.get("target_department"):
            extra = await _slm_blocks(request, query)
            blocks, slm_used = blocks + extra, bool(extra)
        if actor.can("identities:write"):
            first, _, last = (s.get("person") or "").partition(" ")
            dept = await _dept_by_name(db, s.get("target_department"))
            d = s.get("effective_date")
            blocks.append({"type": "action", "label": "Open onboarding form (pre-filled)", "action": "open-onboard",
                           "prefill": {"first_name": first, "last_name": last, "department_id": str(dept.id) if dept else None,
                                       "start_date": d["value"] if d and d.get("resolved") else None}})
        return blocks, slm_used

    if not matches:
        if voice and s.get("person") and not s.get("employee_id"):       # spoken names only; typed text keeps the exact behaviour
            found = await _voice_name_suggestions(db, s["person"])
            if found:
                return blocks + _suggestion_blocks(s["person"], found, ctx, label, s), False
        return blocks + [_text("I couldn't find a matching identity in the directory.")], False
    if len(matches) > 1:
        shown = matches[:10]
        ctx["pending"] = {"label": label, "slots": s, "ask": "person", "question": "Which one do you mean? (name, employee ID or email)",
                          "options": [{"value": m.employee_id, "label": m.full_name, "employee_id": m.employee_id,
                                       "aliases": [m.employee_id, m.email, m.email.split("@")[0]]} for m in shown]}
        more = [] if len(matches) <= 10 else [_text(f"…and {len(matches) - 10} more. Add a surname or an employee ID to narrow it down.")]
        return blocks + [_text(f"{len(matches)} identities match. Which one do you mean? You can reply with the name, employee ID, or “the second one”."),
                         _list([f"{m.full_name} <{m.email}> · {m.employee_id}" for m in shown]), *more], False
    who = matches[0]
    ctx["person"] = {"employee_id": who.employee_id, "name": who.full_name}
    card = await _identity_card(db, who)
    apps, roles = s.get("applications") or [], s.get("access_roles") or []

    if label == "ACCESS_STATUS_QUERY":
        what = ", ".join(apps + roles)
        blocks += card + [_head(f"Current access to {what}" if what else "Current access"),
                          _list(await _entitlements(db, who.id, apps, roles) or ["No matching active or pending access."])]
    else:   # MOVER / ACCESS_REQUEST / ACCESS_REVOCATION / LEAVER -> policy plan
        d = s.get("effective_date")
        prop = Proposal(kind=KIND[label], identity_id=who.id, to_department=s.get("target_department") if label == "MOVER" else None,
                        applications=apps, roles=roles, access_profile=s.get("access_profile") if label == "MOVER" else None, effective_date=date.fromisoformat(d["value"]) if d and d.get("resolved") else None,
                        date_text=d["expression"] if d and not d.get("resolved") else None, text=query[:500])
        plan = await _plan_from(db, prop, actor)
        if plan.choices:
            c = plan.choices[0]
            ctx["pending"] = {"label": label, "slots": s, "ask": c["ask"], "app": c.get("app"), "options": c["options"], "question": plan.questions[0]}
        blocks += card
        src = s.get("source_department")
        if label == "MOVER" and src and plan.from_dept and src.lower() != plan.from_dept.name.lower():
            blocks.append(_text(f"Heads-up: the directory has {who.full_name} in {plan.from_dept.name}, not {src}."))
        blocks += _plan_blocks(plan, actor, prop)
    return blocks, False


_MISSING_Q = {"person": "Who is this for? (full name or employee ID)", "target_department": "Which department should the employee move to?",
              "applications": "Which application or entitlement is this about?"}
_REQUIRED = {"MOVER": ("person", "target_department"), "JOINER": ("person", "target_department"), "LEAVER": ("person",),
             "ACCESS_REQUEST": ("person", "applications"), "ACCESS_REVOCATION": ("person", "applications"), "ACCESS_STATUS_QUERY": ("person",)}


def _missing(label: str, s: dict) -> list[str]:
    out = []
    for f in _REQUIRED.get(label, ()):
        if f == "person":
            ok = s.get("person") or s.get("employee_id") or s.get("subject_reference")
        elif f == "applications":
            ok = s.get("applications") or s.get("access_roles")
        else:
            ok = s.get(f)
        if not ok:
            out.append(f)
    return out


def _options_for(field: str) -> list[dict]:
    cat = nlu.catalogue()
    if field == "target_department":
        return [{"value": d, "label": d, "aliases": nlu.DEPT_ALIASES.get(d, [])} for d in cat["departments"]]
    if field == "applications":
        return [{"value": a, "label": a, "aliases": nlu.APP_ALIASES.get(a, [])} for a in cat["applications"]]
    return []


def _pending_for(label: str, s: dict, missing: list[str], questions: list[str]) -> dict | None:
    """Turn the first missing required slot into a question the next message can answer."""
    for f in ("person", "target_department", "applications"):
        if f in missing and label in _REQUIRED and f in _REQUIRED[label]:
            return {"label": label, "slots": s, "ask": f, "options": _options_for(f), "question": _MISSING_Q[f]}
    return None


def _synthetic(pending: dict, slots: dict) -> dict:
    """Rebuild an NLU-shaped result from remembered state plus the newly supplied answer."""
    label, missing = pending["label"], _missing(pending["label"], slots)
    return {"intent": {"label": label, "confidence": None, "confidence_type": "dialogue_state", "method": "conversation_memory"},
            "slots": slots, "unresolved": {}, "ambiguities": [], "missing_fields": missing,
            "clarification_questions": [_MISSING_Q[m] for m in missing if m in _MISSING_Q],
            "status": "NEEDS_CLARIFICATION" if missing else "PARSED"}


def _resolve_pronoun(res: dict | None, person: dict | None) -> tuple[dict | None, bool]:
    """'Move him to Finance' -> use the last person shown in this chat."""
    if not res or not person or res["intent"]["label"] not in nlu.ASSISTANT_INTENTS:
        return res, False
    s = res["slots"]
    if s.get("person") or s.get("employee_id") or not any(a["type"] == "unresolved_pronoun" for a in res["ambiguities"]):
        return res, False
    r = deepcopy(res)
    r["slots"].update(person=person["name"], employee_id=person["employee_id"])
    r["ambiguities"] = [a for a in r["ambiguities"] if a["type"] != "unresolved_pronoun"]
    r["missing_fields"] = [m for m in r["missing_fields"] if m != "person"]
    r["clarification_questions"] = [q for q in r["clarification_questions"] if "pronoun" not in q] + \
        [_MISSING_Q[m] for m in r["missing_fields"] if m in _MISSING_Q]
    blocking = [a for a in r["ambiguities"] if a["blocking"]]
    r["status"] = "NEEDS_CLARIFICATION" if blocking or r["missing_fields"] else "PARSED"
    return r, True


def _pronoun_unresolved(res: dict | None) -> bool:
    """A lifecycle request that says only 'him/her' and there is no one to resolve it to: ask who, and remember the question."""
    return bool(res and res["status"] == "NEEDS_CLARIFICATION" and res["intent"]["label"] in nlu.ASSISTANT_INTENTS
                and "person" in res["missing_fields"] and any(a["type"] == "unresolved_pronoun" for a in res["ambiguities"]))


def _reask(pending: dict, options: list[dict] | None = None, lead: str = "I didn't catch that.") -> list[dict]:
    opts = options if options is not None else pending.get("options") or []
    blocks = [_text(f"{lead} {pending.get('question', '')}".strip())]
    if 0 < len(opts) <= 10:
        blocks.append(_list([o["label"] for o in opts]))
    blocks.append(_text("You can also say “cancel” to drop this request."))
    return blocks


@router.post("/query")
async def ask(body: QueryIn, request: Request, db: AsyncSession = Depends(get_db),
              actor: Principal = Depends(require_permission("identities:read"))):
    redis, sid = request.app.state.redis, body.session_id
    state = await memory.load(redis, actor.id, sid)
    pending, ctx, via = state.get("pending"), {}, None
    res = await nlu.parse(body.query, date.today())

    # 1) is this an answer to the question I just asked?  (a complete new request that names a person always wins)
    if pending:
        s0 = (res or {}).get("slots", {})
        new_request = nlu.is_actionable(res) and bool(s0.get("person") or s0.get("employee_id"))
        if not new_request:
            if memory.is_cancel(body.query):
                await memory.save(redis, actor.id, sid, {**state, "pending": None})
                return {"blocks": [_text("Okay, I've dropped that request.")], "nlu": {"intent": "CANCEL", "context": "memory"},
                        "source": "Conversation memory (this chat only)."}
            kind, hit = memory.apply_answer(pending, body.query)
            if kind == "one":
                res, via = _synthetic(pending, hit), "answer"
            elif kind == "many":
                pending = {**pending, "options": hit}
                await memory.save(redis, actor.id, sid, {**state, "pending": pending})
                return {"blocks": _reask(pending, lead="That matches more than one."), "nlu": {"intent": pending["label"], "context": "memory"},
                        "source": "Conversation memory (this chat only)."}
            elif not nlu.is_actionable(res):
                blocks, handled = await _legacy(db, actor, body.query)     # e.g. "show pending approvals" mid-conversation still works
                if handled:
                    return {"blocks": blocks, "nlu": None, "source": "Rule-based directory lookup over live records (not a generative model)."}
                return {"blocks": _reask(pending), "nlu": {"intent": pending["label"], "context": "memory"},
                        "source": "Conversation memory (this chat only)."}
        pending = None            # answered, replaced by a new request, or abandoned

    # 2) "him / her" -> the last person shown in this chat
    if via is None:
        res, resolved = _resolve_pronoun(res, state.get("last_person"))
        via = "pronoun" if resolved else None

    if nlu.is_actionable(res) or _pronoun_unresolved(res):
        blocks, used = await _answer_nlu(db, actor, res, request, body.query, ctx, voice=body.input_mode == "voice")
        await memory.save(redis, actor.id, sid, {"pending": ctx.get("pending"), "last_person": ctx.get("person") or state.get("last_person")})
        i = res["intent"]
        src = ("Interpreted by the NLU pipeline with a local language model's suggestions (suggest-only); policy decisions are deterministic."
               if used else "Language understanding by the NLU pipeline (rules + statistical models, not a generative model), answered from live directory records; "
                            "changes are policy-checked.")
        return {"blocks": blocks, "nlu": {"intent": i["label"], "confidence": i["confidence"], "confidence_type": i["confidence_type"],
                                          "method": i["method"], "status": res["status"], "slm_used": used, "context": via}, "source": src}
    blocks, handled = await _legacy(db, actor, body.query)
    if not handled and not scope.in_scope(body.query, res):      # chit-chat / off-topic: refuse politely, model never called
        return {"blocks": [_text(scope.SCOPE_MESSAGE), _list(scope.EXAMPLES)], "nlu": {"intent": "OUT_OF_SCOPE"},
                "source": "Out of scope: this assistant only handles identity and access management (no model was used)."}
    if not handled:
        extra = await _slm_blocks(request, body.query)
        if extra:
            return {"blocks": extra, "nlu": {"intent": "UNKNOWN", "slm_used": True},
                    "source": "The rules engine could not interpret this; a local language model made suggestions (suggest-only)."}
    return {"blocks": blocks, "nlu": None, "source": "Rule-based directory lookup over live records (not a generative model)."}


@router.post("/plan")
async def replan(body: Proposal, db: AsyncSession = Depends(get_db), actor: Principal = Depends(require_permission("identities:read"))):
    """Re-evaluate a proposal (e.g. after choosing an access profile). Read-only: returns the plan blocks, changes nothing."""
    return {"blocks": _plan_blocks(await _plan_from(db, body, actor), actor, body)}


class ExecuteIn(BaseModel):
    proposal: Proposal
    expected_decision: Literal["auto", "approval"]


@router.post("/execute")
async def execute(body: ExecuteIn, request: Request, db: AsyncSession = Depends(get_db),
                  actor: Principal = Depends(require_permission("identities:write"))):
    """Confirm a proposal. The plan is rebuilt and re-decided here; the browser's idea of the decision is only compared."""
    plan = await _plan_from(db, body.proposal, actor)
    if plan.decision != body.expected_decision:
        raise ApiError(409, "policy_changed", f"The policy outcome changed to “{plan.decision}” since you reviewed it. Ask again to see the new plan.")
    if plan.decision not in (policy.AUTO, policy.APPROVAL):
        raise ApiError(422, "not_allowed", "This request cannot be submitted.")
    want = {(l.entitlement_id, l.action) for l in plan.lines}
    rtype = {"mover": "mover", "leaver": "leaver"}.get(plan.kind, "privilege")
    for r in (await db.execute(select(LifecycleRequest).where(LifecycleRequest.identity_id == plan.identity.id, LifecycleRequest.request_type == rtype,
                                                              LifecycleRequest.status == "pending_approval"))).scalars():
        have = {(d.entitlement_id, d.action) for d in (await db.execute(select(LifecycleRequestEntitlement).where(
            LifecycleRequestEntitlement.request_id == r.id))).scalars()}
        if have == want and r.to_department_id == (plan.to_dept.id if plan.kind == "mover" and plan.to_dept else None):
            raise ApiError(409, "duplicate_request", f"An identical request (REQ-{r.ref_no}) is already awaiting approval.")
    out = await lifecycle.execute_plan(db, request, actor, plan, body.proposal.text)
    await invalidate(request)
    if out["decision"] == policy.AUTO:
        msg = (f"{out['ref']} applied." if out["applied"] else f"{out['ref']} approved and scheduled for {out['scheduled_for']}.")
        note = "No live connector is configured, so no external provisioning was executed." if out["applied"] else "It will be applied on that date by the governance scheduler (or `python -m scripts.apply_due`)."
    else:
        msg, note = f"{out['ref']} submitted for approval.", "It is now in the approvals queue."
    blocks = [_head(msg), _text(note)] + ([{"type": "action", "label": "Open approvals queue", "action": "nav:approvals"}] if out["decision"] == policy.APPROVAL else [])
    return {"blocks": blocks, **out}
