"""Governance agent: open orphan / privilege-creep findings -> investigation -> remediation PROPOSALS for a human approver.

For each open finding (worst first, at most `limit` per run, skipping ones that already have a proposal):
  1. Investigator: evidence from the finding plus, for creep, the entitlement's provenance (explain_entitlement_origin). With an LLM,
     the investigator also gives keep/review/revoke advice; "keep" means no proposal is made (the advice is recorded instead).
  2. Remediation planner (deterministic): creep -> revoke that entitlement; a leaver/expired account -> offboard (or revoke all if
     already terminated). Rules a tool can't fix (no owner, dormant, departed manager) get advice only.
  3. Action Gateway with min_decision="approval": the change is ALWAYS queued for a person, even revocations that policy would
     auto-approve. The agent acts as a dedicated, disabled system account, so every proposal is attributable and it cannot log in.

The result is written back to the finding (details.remediation) and audited as agent.remediation_proposed.
"""
from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import case, select

from app.agents import capabilities, llm_agents
from app.agents.contract import ToolCall
from app.agents.gateway import ActionGateway, ToolContext
from app.core.security import hash_password
from app.models import Entitlement, GovernanceFinding, Identity, IdentityEntitlement
from app.models.auth import User
from app.services import audit
from app.services.accounts import Principal

log = logging.getLogger("identityos.agent.governance")
SYSTEM_EMAIL = "governance-agent@identityos.internal"
SYSTEM_NAME = "Governance Agent"
ADVICE_ONLY = {"dormant_account": "Confirm with the person's manager whether the account is still needed, then offboard or keep it.",
               "no_owner": "Assign an owner (manager or sponsor) for this account.",
               "manager_departed": "Assign a new manager for this person."}
_SEVERITY = case({"critical": 0, "high": 1, "medium": 2, "low": 3}, value=GovernanceFinding.severity, else_=4)


async def system_principal(db) -> Principal:
    """The agent's own identity: a portal user that is disabled (cannot sign in) and only ever used server-side."""
    u = (await db.execute(select(User).where(User.email == SYSTEM_EMAIL))).scalar_one_or_none()
    if u is None:
        u = User(email=SYSTEM_EMAIL, full_name=SYSTEM_NAME, status="disabled", password_hash=await hash_password(secrets.token_urlsafe(32)))
        db.add(u)
        await db.commit()
    return Principal(id=str(u.id), email=u.email, full_name=u.full_name, status="active", roles=["governance_agent"],
                     permissions=["identities:read", "identities:write", "governance:read"])


async def _held_names(db, identity_id) -> list[str]:
    return list((await db.execute(select(Entitlement.name).join(IdentityEntitlement, IdentityEntitlement.entitlement_id == Entitlement.id)
                                  .where(IdentityEntitlement.identity_id == identity_id,
                                         IdentityEntitlement.status.in_(("active", "pending"))))).scalars())


def _call_for(f: GovernanceFinding, ident: Identity, held: list[str]) -> ToolCall | None:
    why = f"Governance remediation: {f.title}"[:300]
    if f.rule == "excess_access":
        ent = (f.details or {}).get("entitlement")
        return ToolCall(tool="modify_user_access", args={"identity_id": str(ident.id), "change": "access_revocation", "entitlements": [ent],
                                                         "justification": why}, proposed_by="governance") if ent else None
    if f.rule in ("leaver_with_access", "expired_still_active"):
        if ident.lifecycle_state == "terminated":      # already offboarded: only the access is left to take away
            return ToolCall(tool="modify_user_access", args={"identity_id": str(ident.id), "change": "access_revocation",
                                                             "entitlements": held[:10], "justification": why}, proposed_by="governance") if held else None
        return ToolCall(tool="deprovision_user", args={"identity_id": str(ident.id), "reason": why}, proposed_by="governance")
    return None


async def remediate(sessionmaker, redis, settings, llm=None, *, limit: int = 10, finding_ids: list[uuid.UUID] | None = None) -> dict:
    """One remediation pass. Returns {"proposed": [...], "advice": [...], "skipped": [...]}."""
    out = {"proposed": [], "advice": [], "skipped": []}
    async with sessionmaker() as db:
        actor = await system_principal(db)
        q = select(GovernanceFinding).where(GovernanceFinding.status == "open")
        if finding_ids:
            q = q.where(GovernanceFinding.id.in_(finding_ids))
        findings = [f for f in (await db.execute(q.order_by(_SEVERITY, GovernanceFinding.first_detected_at))).scalars()
                    if not (f.details or {}).get("remediation")][:limit]
        work = [(f.id, f.rule, f.title, f.identity_id, dict(f.details or {})) for f in findings]

    for fid, rule, title, identity_id, details in work:
        async with sessionmaker() as db:
            f = await db.get(GovernanceFinding, fid)
            ident = await db.get(Identity, identity_id)
            entry = {"finding_id": str(fid), "rule": rule, "identity": ident.full_name, "title": title}
            cap = capabilities.mint(actor, tools={"modify_user_access", "deprovision_user", "explain_entitlement_origin"},
                                    targets={str(ident.id)})
            ctx = ToolContext(db=db, actor=actor, cap=cap, redis=redis, settings=settings, user_text=title, min_decision="approval")

            evidence = {"finding": {"rule": rule, "title": title, **details}, "person": ident.full_name, "state": ident.lifecycle_state}
            if rule == "excess_access" and details.get("entitlement"):
                r = await ActionGateway().run(ctx, ToolCall(tool="explain_entitlement_origin", proposed_by="governance",
                                                            args={"identity_id": str(ident.id), "entitlement": details["entitlement"]}))
                if r.ok:
                    evidence["provenance"] = r.data.get("entitlements")
            advice = await llm_agents.investigate(llm, evidence) if llm else None
            note = {"at": datetime.now(timezone.utc).isoformat(), "by": SYSTEM_NAME,
                    "advice": {"recommendation": advice["recommendation"], "summary": advice["summary"]} if advice else None}

            if rule in ADVICE_ONLY:
                note["status"], note["next_step"] = "advice_only", ADVICE_ONLY[rule]
                out["advice"].append({**entry, "next_step": ADVICE_ONLY[rule]})
            elif advice and advice["recommendation"] == "keep":
                note["status"] = "kept_on_advice"
                out["advice"].append({**entry, "next_step": "The investigator found this access justified; no change proposed."})
            else:
                call = _call_for(f, ident, await _held_names(db, ident.id))
                if call is None:
                    out["skipped"].append({**entry, "why": "nothing to remediate"})
                    continue
                preview = await ActionGateway().run(ctx, call)
                result = (await ActionGateway().run(ctx, call, mode="commit", expected_decision=preview.decision)
                          if preview.ok and preview.decision == "approval" else preview)
                if not result.ok:
                    out["skipped"].append({**entry, "why": result.error or result.decision, "reasons": list(result.reasons)[:2]})
                    continue
                note.update(status="proposed", ref=result.audit_ref, tool=call.tool)
                out["proposed"].append({**entry, "ref": result.audit_ref, "tool": call.tool})

            f = await db.get(GovernanceFinding, fid)           # re-load: the gateway's commit/rollback may have expired it
            f.details = {**(f.details or {}), "remediation": note}
            audit.record(db, None, "agent.remediation_proposed" if note.get("ref") else "agent.remediation_advice", actor_id=actor.id,
                         actor_label=actor.email, target_type="identity", target_id=ident.id, target_label=ident.email,
                         category="risk_alert", severity="info", details={"finding": str(fid), "rule": rule, **{k: v for k, v in note.items() if k != "advice"},
                                                                          "recommendation": (advice or {}).get("recommendation")})
            await db.commit()
    log.info("governance remediation: %d proposed, %d advice, %d skipped", len(out["proposed"]), len(out["advice"]), len(out["skipped"]))
    return out
