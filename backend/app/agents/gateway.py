"""Action Gateway: the Policy Enforcement Point. The ONLY component in the agent layer that executes a tool.

Every call, from any agent (or the MCP server), passes the same checks in order; the first failure blocks it and is audited:

  1 known tool          the name is in the registry whitelist             -> unknown_tool        (hallucinated tool)
  2 schema              strict Pydantic validation, no extra fields       -> schema_invalid      (smuggled / malformed args)
  3 capability          token is the actor's, unexpired, covers tool+target -> capability_denied
  4 permission          the human's portal permission, never model output -> forbidden
  5 catalogue           departments / applications / entitlements exist   -> unknown_catalogue_value
  6 policy (PDP)        plan rebuilt server-side by policy.build_plan; the agent's idea of the decision is never used
  7 verifier            agent-layer rules (self-grant, high-risk grants); can only make the decision stricter
  8 idempotency         same actor+tool+args within 24h, and identical pending request -> duplicate
  9 execute + audit     one transaction through lifecycle / onboarding; audit row carries trace_id, call_id, plan_id

Modes: "preview" runs 1-7 and returns the decision (nothing is written); "commit" runs 1-9 and requires the decision the human
confirmed (`expected_decision`) to still hold, otherwise it fails with policy_changed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import ValidationError
from sqlalchemy import select

from app.agents import capabilities
from app.agents.contract import ToolCall, ToolResult
from app.agents.security import privilege
from app.agents.tools.registry import REGISTRY, ToolSpec
from app.core.errors import ApiError
from app.models import Identity, LifecycleRequest, LifecycleRequestEntitlement
from app.services import audit, nlu, policy
from app.services.accounts import Principal

log = logging.getLogger("identityos.agent.gateway")
IDEMPOTENCY_TTL_S = 24 * 3600
EXECUTABLE = (policy.AUTO, policy.APPROVAL)


@dataclass
class ToolContext:
    db: Any                              # AsyncSession
    actor: Principal
    cap: capabilities.Capability
    request: Any = None                  # starlette Request (None for system callers: scheduler, MCP)
    redis: Any = None
    settings: Any = None
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    user_text: str = ""                  # the (sanitised) human message, for the request record only


class Blocked(Exception):
    def __init__(self, code: str, message: str, reasons: list[str] | None = None):
        super().__init__(message)
        self.code, self.message, self.reasons = code, message, reasons or [message]


class ActionGateway:
    def __init__(self, registry: dict[str, ToolSpec] | None = None, catalogue=None):
        self.registry = registry if registry is not None else REGISTRY
        self._catalogue = catalogue or nlu.catalogue

    # ─────────────────────────── public API
    async def run(self, ctx: ToolContext, call: ToolCall, *, mode: Literal["preview", "commit"] = "preview",
                  expected_decision: str | None = None) -> ToolResult:
        try:
            spec, args = self._admit(ctx, call)
            if spec.kind == "read":
                await self._check_target(ctx, spec, args)
                return ToolResult(call_id=call.call_id, tool=spec.name, ok=True, decision=policy.AUTO, data=await spec.run(ctx, args))
            prepared = await self._decide(ctx, spec, args)
            if mode == "preview":
                return ToolResult(call_id=call.call_id, tool=spec.name, ok=True, decision=prepared.decision, data=prepared.summary,
                                  reasons=tuple(prepared.reasons))
            return await self._commit(ctx, call, spec, args, prepared, expected_decision)
        except Blocked as b:
            await self._audit_block(ctx, call, b)
            return ToolResult(call_id=call.call_id, tool=call.tool, ok=False, decision="blocked", error=b.code, reasons=tuple(b.reasons))
        except ApiError as e:            # domain validation from the services (unknown department, not found, ...): not an attack
            return ToolResult(call_id=call.call_id, tool=call.tool, ok=False, error=e.code, reasons=(e.message,))

    # ─────────────────────────── checks 1-5
    def _admit(self, ctx: ToolContext, call: ToolCall) -> tuple[ToolSpec, Any]:
        spec = self.registry.get(call.tool)
        if spec is None:
            raise Blocked("unknown_tool", f"“{call.tool}” is not an allowed tool.")
        try:
            args = spec.args.model_validate(call.args)
        except ValidationError as e:
            raise Blocked("schema_invalid", "The tool arguments are invalid.",
                          [f"{'.'.join(map(str, err['loc'])) or 'args'}: {err['msg']}" for err in e.errors()[:5]])
        cap = ctx.cap
        if cap.actor_id != ctx.actor.id:
            raise Blocked("capability_denied", "The capability belongs to someone else.")
        if cap.expired():
            raise Blocked("capability_denied", "The capability has expired.")
        if not cap.allows_tool(spec.name):
            raise Blocked("capability_denied", f"This conversation is not allowed to use {spec.name}.")
        target = getattr(args, spec.target_arg) if spec.target_arg else None
        if target is not None and not cap.allows_target(target):
            raise Blocked("capability_denied", "This conversation is not allowed to act on that identity.")
        if not ctx.actor.can(spec.permission):
            raise Blocked("forbidden", f"Your role does not allow {spec.name}.")
        self._check_catalogue(spec, args)
        return spec, args

    def _check_catalogue(self, spec: ToolSpec, args) -> None:
        cat = self._catalogue() or {}
        for arg, kind in spec.catalogue:
            known = {x.lower() for x in cat.get(kind) or []}
            if not known:                # catalogue not loaded (NLU disabled): the services still validate against the DB
                continue
            v = getattr(args, arg)
            for item in (v if isinstance(v, list) else [v] if v else []):
                if item.lower() not in known:
                    raise Blocked("unknown_catalogue_value", f"“{item}” is not a known {kind[:-1]}.")

    async def _check_target(self, ctx: ToolContext, spec: ToolSpec, args) -> None:
        """Self-service reads: someone without identities:read may only inspect their own identity."""
        if not spec.target_arg or ctx.actor.can("identities:read"):
            if spec.target_arg and not await ctx.db.get(Identity, getattr(args, spec.target_arg)):
                raise ApiError(404, "not_found", "Identity not found.")
            return
        ident = await ctx.db.get(Identity, getattr(args, spec.target_arg))
        if not ident or not privilege.is_self(ctx.actor.email, ident.email):
            raise Blocked("forbidden", "You can only look at your own access.")

    # ─────────────────────────── checks 6-7
    async def _decide(self, ctx: ToolContext, spec: ToolSpec, args):
        prepared = await spec.prepare(ctx, args)
        if prepared.plan is not None:
            v = privilege.verify(prepared.plan, ctx.actor.email)
            if v.decision != prepared.decision:
                prepared.decision = v.decision
                prepared.plan.decision = v.decision
                prepared.reasons = v.reasons + prepared.reasons
                prepared.plan.reasons = prepared.reasons
            prepared.summary = {**prepared.summary, "verifier_rules": v.rules}
        prepared.summary = {**prepared.summary, "decision": prepared.decision}
        return prepared

    # ─────────────────────────── checks 8-9
    async def _commit(self, ctx: ToolContext, call: ToolCall, spec: ToolSpec, args, prepared, expected: str | None) -> ToolResult:
        if expected is None or prepared.decision != expected:
            return ToolResult(call_id=call.call_id, tool=spec.name, ok=False, decision=prepared.decision, error="policy_changed",
                              reasons=(f"The policy outcome is now “{prepared.decision}”. Review the new plan before confirming.",
                                       *prepared.reasons), data=prepared.summary)
        if prepared.decision not in EXECUTABLE:
            return ToolResult(call_id=call.call_id, tool=spec.name, ok=False, decision=prepared.decision, error="not_allowed",
                              reasons=tuple(prepared.reasons))
        if prepared.plan is not None:
            dup = await self._duplicate_request(ctx, prepared.plan)
            if dup:
                raise Blocked("duplicate", f"An identical request ({dup}) is already awaiting approval.")
        key = self._idempotency_key(ctx, spec, args)
        if ctx.redis is not None and not await ctx.redis.set(key, call.call_id, nx=True, ex=IDEMPOTENCY_TTL_S):
            raise Blocked("duplicate", "This exact action was already submitted today.")
        try:
            out = await spec.commit(ctx, args, prepared)
        except Exception:
            if ctx.redis is not None:
                await ctx.redis.delete(key)          # failed: allow a retry
            raise
        audit.record(ctx.db, ctx.request, "agent.tool_executed", actor_id=ctx.actor.id, actor_label=ctx.actor.email,
                     target_type="identity", target_id=prepared.target_id or out.get("identity_id"), severity="info", category="provisioning",
                     details={"tool": spec.name, "call_id": call.call_id, "plan_id": call.plan_id, "trace_id": ctx.trace_id,
                              "proposed_by": call.proposed_by, "decision": prepared.decision, "request": out.get("ref")})
        await ctx.db.commit()
        return ToolResult(call_id=call.call_id, tool=spec.name, ok=True, decision=prepared.decision, data={**prepared.summary, **out},
                          reasons=tuple(prepared.reasons), audit_ref=out.get("ref"))

    async def _duplicate_request(self, ctx: ToolContext, plan: policy.Plan) -> str | None:
        want = {(l.entitlement_id, l.action) for l in plan.lines}
        rtype = {"mover": "mover", "leaver": "leaver"}.get(plan.kind, "privilege")
        to_dept = plan.to_dept.id if plan.kind == "mover" and plan.to_dept else None
        for r in (await ctx.db.execute(select(LifecycleRequest).where(LifecycleRequest.identity_id == plan.identity.id,
                                                                      LifecycleRequest.request_type == rtype,
                                                                      LifecycleRequest.status == "pending_approval"))).scalars():
            have = {(d.entitlement_id, d.action) for d in (await ctx.db.execute(select(LifecycleRequestEntitlement).where(
                LifecycleRequestEntitlement.request_id == r.id))).scalars()}
            if have == want and r.to_department_id == to_dept:
                return f"REQ-{r.ref_no}"
        return None

    @staticmethod
    def _idempotency_key(ctx: ToolContext, spec: ToolSpec, args) -> str:
        body = json.dumps({"a": ctx.actor.id, "t": spec.name, "x": args.model_dump(mode="json")}, sort_keys=True)
        return "agent:idem:" + hashlib.sha256(body.encode()).hexdigest()

    async def _audit_block(self, ctx: ToolContext, call: ToolCall, b: Blocked) -> None:
        log.warning("agent tool call blocked: %s %s (%s)", call.tool, b.code, ctx.trace_id)
        try:
            await ctx.db.rollback()
            audit.record(ctx.db, ctx.request, "agent.action_blocked", actor_id=ctx.actor.id, actor_label=ctx.actor.email, severity="medium",
                         outcome="failure", category="risk_alert",
                         details={"tool": call.tool[:64], "code": b.code, "reasons": b.reasons[:5], "call_id": call.call_id,
                                  "plan_id": call.plan_id, "trace_id": ctx.trace_id, "proposed_by": call.proposed_by})
            await ctx.db.commit()
        except Exception:  # noqa: BLE001 - never let audit failure hide the block itself
            log.exception("could not audit blocked agent call")
