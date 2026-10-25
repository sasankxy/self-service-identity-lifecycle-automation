"""Conversation graph (LangGraph): one chat turn = one invocation, state checkpointed per (user, chat session).

    START ─► sentinel ─┬─ blocked ─────────────────────────────────────────────► END
                       └► understand ─┬─ answered / cancelled / re-asked ──────► END
                                      ├► directory  (analytics, chit-chat, SLM) ► END
                                      └► lifecycle ─┬─ read / clarify / denied ► END
                                                    └► confirm ⏸ interrupt ──► END
                                                         resume(confirm) ─► Action Gateway commit

* sentinel    sanitises the text and blocks injection attempts (audited); nothing downstream sees raw input.
* understand  NLU (+ conversation memory: pending question, pronouns). The output is TYPED slots, never instructions.
* directory   the rule-based assistant's read-only analytics answers, unchanged.
* lifecycle   resolves the person, builds ONE whitelisted ToolCall from the slots (deterministic planner) and previews it
              through the Action Gateway, which re-runs the policy engine.
* confirm     LangGraph interrupt(): the turn pauses until POST /agent/resume. The resume must quote the call_id it confirms,
              so a stale button can never approve a different action. Commit goes through the gateway again (policy re-checked).
"""
from __future__ import annotations

import time
from datetime import date
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from app.agents import contract, deps as D, narrator
from app.agents.contract import ToolCall
from app.agents.gateway import ActionGateway, ToolContext
from app.agents.security import injection
from app.agents.security.sanitize import sanitize
from app.models import Identity
from app.services import audit, directory, memory, nlu, policy, scope
from app.services.cache import invalidate

KIND = {"MOVER": "mover", "ACCESS_REQUEST": "access_request", "ACCESS_REVOCATION": "access_revocation"}
SOURCE = {"blocked": "Blocked by the agent's input guard (no model was used).",
          "memory": "Conversation memory (this chat only).",
          "agent": "Multi-agent pipeline: NLU understanding, policy-checked tool calls through the Action Gateway.",
          "directory": "Rule-based directory lookup over live records (not a generative model).",
          "out_of_scope": "Out of scope: this assistant only handles identity and access management (no model was used).",
          "slm": "The rules engine could not interpret this; a local language model made suggestions (suggest-only)."}


class ChatState(TypedDict, total=False):
    # input (per turn)
    text: str
    voice: bool
    # memory (persists across turns via the checkpointer)
    pending: dict | None
    last_person: dict | None
    # per-turn working state
    nlu: dict | None
    intent: dict | None
    via: str | None
    route: str
    call: dict | None
    preview: dict | None
    result: dict | None
    blocks: list[dict]
    source: str
    trace: list[dict]


def _assistant():
    from app.api.v1 import assistant      # lazy: the API module imports app.agents indirectly via main
    return assistant


def _step(state: ChatState, node: str, t0: float, **info) -> list[dict]:
    return [*(state.get("trace") or []), {"node": node, "ms": round((time.perf_counter() - t0) * 1000, 1), **info}]


def _gateway_ctx(db, dep: D.AgentDeps, text_in: str, cap=None) -> ToolContext:
    return ToolContext(db=db, actor=dep.actor, cap=cap or dep.cap, request=dep.request, redis=dep.redis, settings=dep.settings,
                       trace_id=dep.trace_id, user_text=text_in)


# ───────────────────────────────────────── nodes
async def sentinel(state: ChatState) -> dict:
    t0, dep = time.perf_counter(), D.current()
    clean, flags = sanitize(state.get("text") or "")
    v = injection.scan(clean)
    fresh = {"text": clean, "nlu": None, "intent": None, "via": None, "call": None, "preview": None, "result": None, "blocks": [],
             "trace": []}
    if not v.blocked:
        return {**fresh, "route": "understand", "trace": [{"node": "sentinel", "ms": round((time.perf_counter() - t0) * 1000, 1),
                                                            "flags": flags, "blocked": False}]}
    async with dep.sessionmaker() as db:
        audit.record(db, dep.request, "agent.guard_block", actor_id=dep.actor.id, actor_label=dep.actor.email, severity="medium",
                     outcome="failure", category="risk_alert",
                     details={"rules": list(v.rules), "flags": flags, "text": clean[:200], "trace_id": dep.trace_id})
        await db.commit()
    return {**fresh, "route": "end", "source": SOURCE["blocked"],
            "blocks": [narrator.text("I can't act on that request. It looks like an attempt to change how I work or to bypass "
                                     "approvals, so it was blocked and logged."),
                       narrator.text("Ask about a person's access, a department move, an access request or an offboarding instead.")],
            "trace": [{"node": "sentinel", "ms": round((time.perf_counter() - t0) * 1000, 1), "flags": flags, "blocked": True,
                       "rules": list(v.rules)}]}


async def understand(state: ChatState) -> dict:
    """The quarantined extractor: text -> typed intent/slots. Mirrors the rule-based assistant's dialogue handling."""
    t0, A = time.perf_counter(), _assistant()
    text_in, pending, via = state["text"], state.get("pending"), None
    res = await nlu.parse(text_in, date.today())

    if pending:
        s0 = (res or {}).get("slots", {})
        new_request = nlu.is_actionable(res) and bool(s0.get("person") or s0.get("employee_id"))
        if not new_request:
            if memory.is_cancel(text_in):
                return {"pending": None, "route": "end", "source": SOURCE["memory"], "blocks": [narrator.text("Okay, I've dropped that request.")],
                        "trace": _step(state, "understand", t0, outcome="cancelled")}
            kind, hit = memory.apply_answer(pending, text_in)
            if kind == "one":
                res, via = A._synthetic(pending, hit), "answer"
            elif kind == "many":
                pending = {**pending, "options": hit}
                return {"pending": pending, "route": "end", "source": SOURCE["memory"], "blocks": A._reask(pending, lead="That matches more than one."),
                        "trace": _step(state, "understand", t0, outcome="ambiguous_answer")}
            elif not nlu.is_actionable(res):
                return {"nlu": res, "route": "directory", "via": "reask", "trace": _step(state, "understand", t0, outcome="not_an_answer")}
        pending = None

    if via is None:
        res, resolved = A._resolve_pronoun(res, state.get("last_person"))
        via = "pronoun" if resolved else None

    lifecycle_turn = nlu.is_actionable(res) or A._pronoun_unresolved(res)
    intent = contract.from_nlu(res, D.current().actor.id) if lifecycle_turn else None
    return {"nlu": res, "via": via, "pending": pending, "intent": intent.model_dump(mode="json") if intent else None,
            "route": "lifecycle" if lifecycle_turn else "directory",
            "trace": _step(state, "understand", t0, intent=(res or {}).get("intent", {}).get("label"), via=via,
                           status=(res or {}).get("status"))}


async def directory_answer(state: ChatState) -> dict:
    """Non-lifecycle questions: the rule-based assistant's read-only answers (pending approvals, risk lists, name lookups)."""
    t0, dep, A = time.perf_counter(), D.current(), _assistant()
    text_in, pending = state["text"], state.get("pending")
    async with dep.sessionmaker() as db:
        blocks, handled = await A._legacy(db, dep.actor, text_in)
    if handled:
        return {"blocks": blocks, "source": SOURCE["directory"], "trace": _step(state, "directory", t0, handled=True)}
    if state.get("via") == "reask" and pending:
        return {"blocks": A._reask(pending), "source": SOURCE["memory"], "trace": _step(state, "directory", t0, handled=False, reask=True)}
    if not scope.in_scope(text_in, state.get("nlu")):
        return {"blocks": [narrator.text(scope.SCOPE_MESSAGE), narrator.bullets(scope.EXAMPLES)], "source": SOURCE["out_of_scope"],
                "trace": _step(state, "directory", t0, handled=False, out_of_scope=True)}
    extra = await A._slm_blocks(dep.request, text_in) if dep.request is not None else []
    return {"blocks": extra or blocks, "source": SOURCE["slm"] if extra else SOURCE["directory"],
            "trace": _step(state, "directory", t0, handled=False, slm=bool(extra))}


def plan_call(label: str, s: dict, identity_id, text_in: str) -> ToolCall:
    """Deterministic planner: typed slots -> exactly one whitelisted tool call. No model output reaches the arguments."""
    d = s.get("effective_date") or {}
    eff = d.get("value") if d.get("resolved") else None
    if label == "ACCESS_STATUS_QUERY":
        return ToolCall(tool="inspect_user_access", args={"identity_id": str(identity_id), "applications": s.get("applications") or [],
                                                          "entitlements": s.get("access_roles") or []})
    if label == "LEAVER":
        reason = (s.get("reason") or "").strip()
        return ToolCall(tool="deprovision_user", args={"identity_id": str(identity_id), "effective_date": eff,
                                                       "reason": reason if len(reason) >= 3 else "Requested via the IAM assistant"})
    return ToolCall(tool="modify_user_access", args={
        "identity_id": str(identity_id), "change": KIND[label], "to_department": s.get("target_department") if label == "MOVER" else None,
        "access_profile": s.get("access_profile") if label == "MOVER" else None, "applications": s.get("applications") or [],
        "entitlements": s.get("access_roles") or [], "effective_date": eff,
        "date_text": None if d.get("resolved") else d.get("expression"), "justification": f"Requested via AI assistant: {text_in[:400]}"})


async def lifecycle(state: ChatState) -> dict:
    t0, dep, A = time.perf_counter(), D.current(), _assistant()
    res, text_in = state["nlu"], state["text"]
    label, s = res["intent"]["label"], res["slots"]
    ctx: dict = {}

    def out(blocks, route="end", **extra):
        return {"blocks": blocks, "route": route, "source": SOURCE["agent"], "pending": ctx.get("pending"),
                "last_person": ctx.get("person") or state.get("last_person"),
                "trace": _step(state, "lifecycle", t0, intent=label, **{k: v for k, v in extra.items() if k in ("tool", "decision", "error", "outcome")}),
                **{k: v for k, v in extra.items() if k in ("call", "preview")}}

    async with dep.sessionmaker() as db:
        # clarification, joiners and unresolved names: the assistant's dialogue (read-only, no tool call)
        if res["status"] == "NEEDS_CLARIFICATION" or label == "JOINER":
            blocks, _ = await A._answer_nlu(db, dep.actor, res, dep.request, text_in, ctx, voice=dep.voice)
            if res["status"] == "NEEDS_CLARIFICATION" and not ctx.get("pending"):
                ctx["pending"] = A._pending_for(label, s, res["missing_fields"], res["clarification_questions"])
            return out(blocks, outcome="clarify" if label != "JOINER" else "joiner_form")

        blocks: list[dict] = [A._understood(res, dep.actor)] if label != "ACCESS_STATUS_QUERY" else []
        for k, v in (res.get("unresolved") or {}).items():
            blocks.append(narrator.text(f"I didn't recognise {k.replace('_', ' ')}: {', '.join(v) if isinstance(v, list) else v}."))

        matches = await directory.resolve_identities(db, dep.actor, s)
        if not matches:
            if dep.voice and s.get("person") and not s.get("employee_id"):
                found = await A._voice_name_suggestions(db, s["person"])
                if found:
                    return out(blocks + A._suggestion_blocks(s["person"], found, ctx, label, s), outcome="voice_suggestions")
            return out(blocks + [narrator.text("I couldn't find a matching identity in the directory.")], outcome="not_found")
        if len(matches) > 1:
            shown = matches[:10]
            ctx["pending"] = {"label": label, "slots": s, "ask": "person", "question": "Which one do you mean? (name, employee ID or email)",
                              "options": [{"value": m.employee_id, "label": m.full_name, "employee_id": m.employee_id,
                                           "aliases": [m.employee_id, m.email, m.email.split("@")[0]]} for m in shown]}
            return out(blocks + [narrator.text(f"{len(matches)} identities match. Which one do you mean? You can reply with the name, employee ID, or “the second one”."),
                                 narrator.bullets([f"{m.full_name} <{m.email}> · {m.employee_id}" for m in shown])], outcome="ambiguous_person")
        who: Identity = matches[0]
        ctx["person"] = {"employee_id": who.employee_id, "name": who.full_name}

        call = plan_call(label, s, who.id, text_in)
        cap = dep.cap.narrowed(targets={str(who.id)})          # this turn may only touch the person it resolved
        result = (await ActionGateway().run(_gateway_ctx(db, dep, text_in, cap), call)).model_dump(mode="json")
        card = await directory.identity_card(db, who)

    if not result["ok"]:
        return out(blocks + card + narrator.error_blocks(result), tool=call.tool, error=result["error"], outcome="error")
    if label == "ACCESS_STATUS_QUERY":
        what = ", ".join((s.get("applications") or []) + (s.get("access_roles") or []))
        return out(card + [narrator.head(f"Current access to {what}" if what else "Current access"),
                           narrator.bullets(result["data"]["access"] or ["No matching active or pending access."])], tool=call.tool, outcome="read")

    data = result["data"]
    src = s.get("source_department")
    if label == "MOVER" and src and data.get("from_department") and src.lower() != data["from_department"].lower():
        blocks.append(narrator.text(f"Heads-up: the directory has {who.full_name} in {data['from_department']}, not {src}."))
    blocks += card + narrator.preview_blocks(result)
    if data.get("choices"):
        c = data["choices"][0]
        ctx["pending"] = {"label": label, "slots": s, "ask": c["ask"], "app": c.get("app"), "options": c["options"],
                          "question": (data.get("questions") or ["Which one?"])[0]}
    if result["decision"] in (policy.AUTO, policy.APPROVAL):
        can_write = dep.actor.can("identities:write")
        blocks += narrator.confirm_blocks(call.call_id, result["decision"], data.get("effective_date"), can_write)
        if can_write:
            return out(blocks, route="confirm", tool=call.tool, decision=result["decision"], call=call.model_dump(mode="json"),
                       preview=result)
    return out(blocks, tool=call.tool, decision=result["decision"])


async def confirm(state: ChatState) -> dict:
    """Pause for the human. Resume value: {"confirm": bool, "call_id": str}."""
    call, preview = state["call"], state["preview"]
    answer = interrupt({"call_id": call["call_id"], "tool": call["tool"], "decision": preview["decision"]})
    t0, dep = time.perf_counter(), D.current()
    if not isinstance(answer, dict) or answer.get("call_id") != call["call_id"]:
        return {"blocks": [narrator.text("That confirmation is out of date, so nothing was changed. Please review the latest plan.")],
                "call": None, "preview": None, "trace": _step(state, "confirm", t0, outcome="stale")}
    if not answer.get("confirm"):
        return {"blocks": [narrator.text("Cancelled. Nothing was changed.")], "call": None, "preview": None,
                "trace": _step(state, "confirm", t0, outcome="cancelled")}
    tc = ToolCall.model_validate(call)
    async with dep.sessionmaker() as db:
        result = (await ActionGateway().run(_gateway_ctx(db, dep, state.get("text") or ""), tc, mode="commit",
                                            expected_decision=preview["decision"])).model_dump(mode="json")
    if result["ok"] and dep.request is not None:
        await invalidate(dep.request)
    blocks = narrator.done_blocks(result) if result["ok"] else narrator.error_blocks(result)
    return {"blocks": blocks, "result": result, "call": None, "preview": None, "source": SOURCE["agent"],
            "trace": _step(state, "confirm", t0, outcome="committed" if result["ok"] else result["error"], tool=tc.tool,
                           decision=result.get("decision"), ref=result.get("audit_ref"))}


def _route(state: ChatState) -> str:
    return state.get("route") or "end"


def build(checkpointer: Any):
    g = StateGraph(ChatState)
    g.add_node("sentinel", sentinel)
    g.add_node("understand", understand)
    g.add_node("directory", directory_answer)
    g.add_node("lifecycle", lifecycle)
    g.add_node("confirm", confirm)
    g.add_edge(START, "sentinel")
    g.add_conditional_edges("sentinel", _route, {"understand": "understand", "end": END})
    g.add_conditional_edges("understand", _route, {"lifecycle": "lifecycle", "directory": "directory", "end": END})
    g.add_edge("directory", END)
    g.add_conditional_edges("lifecycle", _route, {"confirm": "confirm", "end": END})
    g.add_edge("confirm", END)
    return g.compile(checkpointer=checkpointer)
