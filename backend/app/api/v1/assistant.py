"""Directory assistant: read-only, rule-based lookups over real database records.

It is NOT a generative model and it never performs actions; it answers from persisted data only,
and says so. (Wiring an LLM on top is a later step.)
"""
import re

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import csrf
from app.core.deps import get_db, require_permission
from app.models import AccessProfile, ApprovalRequest, Department, Identity, IdentityEntitlement, LifecycleRequest
from app.services import stats
from app.services.accounts import Principal

router = APIRouter(prefix="/assistant", tags=["assistant"], dependencies=[Depends(csrf.csrf_protect)])
STOP = set("""the and for with show list who what which are any all has have how many does about from that this please give tell find lookup look
risk score scores high low medium flagged anomalies anomaly pending approval approvals approve identity identities account accounts access
onboard onboarding hire offboard offboarding revoke leave leaver leavers joiner joiners mover movers status check inspect review report
user users employee employees""".split())


class QueryIn(BaseModel):
    query: str = Field(min_length=1, max_length=500)


def _kv(items): return {"type": "kv", "items": [[k, "—" if v is None else str(v)] for k, v in items]}
def _text(t): return {"type": "text", "text": t}
def _list(items): return {"type": "list", "items": items}
def _head(t): return {"type": "heading", "text": t}


@router.post("/query")
async def ask(body: QueryIn, db: AsyncSession = Depends(get_db), actor: Principal = Depends(require_permission("identities:read"))):
    low = body.query.lower()
    blocks: list[dict] = []
    words = [w for w in re.findall(r"[a-z0-9.@'_-]+", low) if len(w) >= 3 and w not in STOP]

    # 1. a specific identity?
    matches: list[Identity] = []
    if words:
        conds = [or_(func.lower(Identity.full_name).like(f"%{w}%"), func.lower(Identity.email).like(f"%{w}%")) for w in words]
        cand = (await db.execute(select(Identity).where(or_(*conds)).limit(60))).scalars().all()
        scored = [(sum(w in (c.full_name + " " + c.email).lower() for w in words), c) for c in cand]
        best = max((s for s, _ in scored), default=0)
        matches = [c for s, c in scored if s == best and best > 0]
    if 1 <= len(matches) <= 3:
        for i in matches:
            dept = await db.get(Department, i.department_id) if i.department_id else None
            prof = await db.get(AccessProfile, i.access_profile_id) if i.access_profile_id else None
            n_active = (await db.execute(select(func.count()).select_from(IdentityEntitlement).where(
                IdentityEntitlement.identity_id == i.id, IdentityEntitlement.status.in_(("active", "pending"))))).scalar_one()
            reqs = (await db.execute(select(LifecycleRequest.ref_no, LifecycleRequest.request_type, LifecycleRequest.status).where(
                LifecycleRequest.identity_id == i.id).order_by(LifecycleRequest.created_at.desc()).limit(3))).all()
            blocks += [_head(i.full_name), _kv([
                ("Email", i.email), ("Department", dept.name if dept else None), ("Access profile", prof.name if prof else None),
                ("Lifecycle state", i.lifecycle_state), ("Risk score", f"{i.risk_score} / 100 ({stats.risk_level(i.risk_score)})"),
                ("Current entitlements", n_active), ("Recent requests", ", ".join(f"REQ-{n} {t} ({s})" for n, t, s in reqs) or "none")])]
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
        blocks += [_text("I can look things up in the directory. Try: an employee's name or email, “high-risk identities”, or “pending approvals”.")]
    return {"blocks": blocks, "source": "Rule-based directory lookup over live records (not a generative model)."}
