"""Conversation graph (LangGraph): one chat turn = one invocation, state checkpointed per (user, chat session).

    START ─► sentinel ─┬─ blocked ──────────────────────────────────────────────► END
                       └► understand ─┬─ answered / cancelled / re-asked ───────► END
                                      ├► directory    (analytics, chit-chat, SLM) ► END
                                      ├► investigate  ("why does X have Y?")      ► END
                                      ├► lifecycle ─┬─ read / clarify / denied ─► END
                                      │             └────────────┐
                                      └► multi (compound) ───────┴► confirm ⏸ interrupt ─► END
                                                                     resume(plan_id) ─► Action Gateway commit, step by step

* sentinel    sanitises the text and blocks injection attempts (audited); nothing downstream sees raw input.
* understand  NLU (+ conversation memory: pending question, pronouns) and compound-request splitting. Output: typed slots.
* quarantine  (security/quarantine.py) the boundary: the planner receives `Slots` only; raw text never reaches a tool argument.
* lifecycle   resolves the person, planner -> ONE whitelisted ToolCall, previewed through the Action Gateway (policy re-run).
* multi       a compound request -> an ActionPlan of up to 3 steps; each previewed, then verified TOGETHER (cross-step SoD,
              offboard + change), then one confirmation for the whole plan.
* investigate read-only provenance of held access (explain_entitlement_origin).
* confirm     LangGraph interrupt(): the turn pauses until POST /agent/resume quoting the plan_id, so a stale button can never
              approve a different plan. Each step commits through the gateway again; the first failure stops the rest.
"""
from __future__ import annotations

import re
import time
import uuid
from datetime import date
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

import asyncio

from app.agents import contract, deps as D, llm_agents, narrator, planner
from app.agents.contract import ToolCall
from app.agents.gateway import ActionGateway, ToolContext
from app.agents.security import injection
from app.agents.security.quarantine import quarantine
from app.agents.security.sanitize import sanitize
from app.agents.tools.registry import REGISTRY
from app.models import Identity
from app.services import audit, directory, memory, nlu, policy, scope
from app.services.cache import invalidate

WHY_RE = re.compile(r"^\s*why\s+(?:(?:does|do|did|is|has)\s+)?(?P<who>.+?)\s+(?:still\s+)?(?:have|has|hold|holds|got|get)\s+"
                    r"(?:access\s+to\s+|the\s+)?(?P<what>.+?)(?:\s+(?:access|rights|permissions?|role|entitlement))?\s*\??\s*$", re.IGNORECASE)
COPILOT_RE = re.compile(r"\b(?:brief|should\s+(?:i|we)\s+(?:approve|reject)|assess|analy[sz]e|review|summary|summari[sz]e|explain)\b"
                        r".*?\bREQ[-\s]?(?P<ref>\d{1,8})\b", re.IGNORECASE)
PRONOUN_RE = re.compile(r"\b(he|him|his|she|her|hers|they|them|their)\b", re.IGNORECASE)
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
    plan: dict | None            # {"plan_id", "steps": [ToolCall dicts], "decisions": [...]}, awaiting confirmation
    clauses: list[dict] | None   # NLU results of a compound request, one per clause
    investigation: dict | None   # {"who", "what"} of a "why does X have Y?" question
    nlu_pre: dict | None         # NLU result computed in parallel with the sentinel's model check
    copilot_ref: int | None      # REQ number the approver copilot should brief
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
    fresh = {"text": clean, "nlu": None, "intent": None, "via": None, "plan": None, "clauses": None, "investigation": None, "result": None,
             "nlu_pre": None, "copilot_ref": None, "blocks": [], "trace": []}
    score = None
    if not v.blocked:
        # fan out: the guard model judges the text while the NLU already parses it (the parse is discarded if blocked)
        verdict, pre = await asyncio.gather(llm_agents.judge(dep.llm, clean) if dep.llm else _none(), nlu.parse(clean, date.today()))
        score = None if verdict is None else verdict["category"]
        if not (verdict and verdict["violation"]):
            return {**fresh, "nlu_pre": pre, "route": "understand",
                    "trace": [{"node": "sentinel", "ms": round((time.perf_counter() - t0) * 1000, 1), "flags": flags, "blocked": False,
                               "guard": score}]}
        v = injection.Verdict(blocked=True, rules=("llm_guard",))
    async with dep.sessionmaker() as db:
        audit.record(db, dep.request, "agent.guard_block", actor_id=dep.actor.id, actor_label=dep.actor.email, severity="medium",
                     outcome="failure", category="risk_alert",
                     details={"rules": list(v.rules), "flags": flags, "text": clean[:200], "trace_id": dep.trace_id, "guard": score})
        await db.commit()
    return {**fresh, "route": "end", "source": SOURCE["blocked"],
            "blocks": [narrator.text("I can't act on that request. It looks like an attempt to change how I work or to bypass "
                                     "approvals, so it was blocked and logged."),
                       narrator.text("Ask about a person's access, a department move, an access request or an offboarding instead.")],
            "trace": [{"node": "sentinel", "ms": round((time.perf_counter() - t0) * 1000, 1), "flags": flags, "blocked": True,
                       "rules": list(v.rules), "guard": score}]}


async def _none():
    return None


async def understand(state: ChatState) -> dict:
    """The quarantined extractor: text -> typed intent/slots. Mirrors the rule-based assistant's dialogue handling."""
    t0, A = time.perf_counter(), _assistant()
    text_in, pending, via = state["text"], state.get("pending"), None
    if not pending:
        c = COPILOT_RE.search(text_in)
        if c:
            return {"route": "copilot", "copilot_ref": int(c["ref"]), "trace": _step(state, "understand", t0, intent="BRIEF")}
        m = WHY_RE.match(text_in)
        if m:
            return {"route": "investigate", "investigation": {"who": m["who"].strip(), "what": m["what"].strip(" .?")},
                    "trace": _step(state, "understand", t0, intent="INVESTIGATE")}
        clauses = await _compound(text_in, state.get("last_person"))
        if clauses:
            return {"route": "multi", "clauses": clauses, "pending": None,
                    "trace": _step(state, "understand", t0, intent="COMPOUND", steps=[c["intent"]["label"] for c in clauses])}
    res = state.get("nlu_pre") or await nlu.parse(text_in, date.today())

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

    llm = D.current().llm
    if llm and via is None and scope.in_scope(text_in, res):
        if res and (any("more than one request" in q for q in res.get("clarification_questions") or []) or _mixed_actions(text_in) >= 2):
            steps = await llm_agents.decompose(llm, text_in, nlu.catalogue(), state.get("last_person"), A._REQUIRED, date.today())
            if steps and all(r["status"] == "PARSED" for r in steps):
                return {"route": "multi", "clauses": steps, "pending": None,
                        "trace": _step(state, "understand", t0, intent="COMPOUND", via="llm_planner", steps=[r["intent"]["label"] for r in steps])}
        weak = not nlu.is_actionable(res) or (res or {}).get("status") == "NEEDS_CLARIFICATION"
        if weak:   # the NLU is unsure: ask the extractor agent; keep its reading only if it is more complete
            ext = await llm_agents.extract(llm, text_in, nlu.catalogue(), state.get("last_person"), A._REQUIRED, date.today())
            if ext and nlu.is_actionable(ext) and (not nlu.is_actionable(res) or len(ext["missing_fields"]) < len(res.get("missing_fields") or [])):
                res, via = ext, "llm_extractor"

    lifecycle_turn = nlu.is_actionable(res) or A._pronoun_unresolved(res)
    intent = contract.from_nlu(res, D.current().actor.id, source="slm" if via == "llm_extractor" else "nlu") if lifecycle_turn else None
    return {"nlu": res, "via": via, "pending": pending, "intent": intent.model_dump(mode="json") if intent else None,
            "route": "lifecycle" if lifecycle_turn else "directory",
            "trace": _step(state, "understand", t0, intent=(res or {}).get("intent", {}).get("label"), via=via,
                           status=(res or {}).get("status"))}


async def _compound(text_in: str, last_person: dict | None) -> list[dict] | None:
    """Understand each clause of a compound request on its own; a pronoun in a later clause refers to the previous clause's person.
    Only all-write, fully-specified compounds are planned as multi-step; anything else falls back to the single-intent path."""
    parts = planner.split_clauses(text_in)
    if len(parts) < 2:
        return None
    A, out, prev = _assistant(), [], last_person
    for part in parts:
        r = await nlu.parse(part, date.today())
        r, _ = A._resolve_pronoun(r, prev)
        if r and prev and not (r["slots"].get("person") or r["slots"].get("employee_id")) and PRONOUN_RE.search(part):
            # "…and remove HIS GitHub access": the NLU does not flag possessives, so carry the previous clause's person
            s = {**r["slots"], "person": prev.get("name"), "employee_id": prev.get("employee_id")}
            missing = A._missing(r["intent"]["label"], s)
            blocking = [a for a in r.get("ambiguities") or [] if a.get("blocking") and a.get("type") != "unresolved_pronoun"]
            r = {**r, "slots": s, "missing_fields": missing, "status": "NEEDS_CLARIFICATION" if missing or blocking else "PARSED"}
        if not r or r["status"] != "PARSED" or r["intent"]["label"] not in planner.WRITE_LABELS:
            return None
        s = r["slots"]
        if not (s.get("person") or s.get("employee_id")):
            return None
        prev = {"name": s.get("person"), "employee_id": s.get("employee_id")}
        out.append(r)
    return out


_ACTION_CUES = {
    "move": re.compile(r"\b(?:move|moving|moves|transfer\w*|shift\w*|relocat\w*)\b", re.IGNORECASE),
    "grant": re.compile(r"\b(?:give|grant|add|provide|needs?|wants?)\b", re.IGNORECASE),
    "revoke": re.compile(r"\b(?:remove|revoke|take away|must go|drop|disable|cut off|no longer)\b", re.IGNORECASE),
    "leave": re.compile(r"\b(?:offboard|terminate|deprovision|leaving|last day)\b", re.IGNORECASE),
}


def _mixed_actions(text_in: str) -> int:
    """How many different kinds of change a message mentions; two or more means the planner agent should decompose it."""
    return sum(1 for rx in _ACTION_CUES.values() if rx.search(text_in))


async def _summarised(blocks: list[dict], facts: dict) -> list[dict]:
    """Narrator agent: prepend a grounded one-line summary when an LLM is available; unchanged blocks otherwise."""
    llm = D.current().llm
    s = await llm_agents.narrate(llm, facts) if llm else None
    return ([narrator.ai(s)] if s else []) + blocks


def _dropped_blocks(dropped: dict) -> list[dict]:
    return [narrator.text(f"I ignored {k.replace('_', ' ')} I couldn't match to the directory: {', '.join(v)}.") for k, v in dropped.items()]


SELF_HELP = ["What access do I have?", "Why do I have Salesforce access?", "I need access to GitHub",
             "Remove my Zoom access"]


def _self_help(lead: str) -> list[dict]:
    return [narrator.text(lead), narrator.text("You can ask about or change your own access, for example:"), narrator.bullets(SELF_HELP),
            narrator.text("Requests for new access always go to an approver. Moves and offboarding are requested by your manager or HR.")]


async def directory_answer(state: ChatState) -> dict:
    """Non-lifecycle questions: the rule-based assistant's read-only answers (pending approvals, risk lists, name lookups)."""
    t0, dep, A = time.perf_counter(), D.current(), _assistant()
    text_in, pending = state["text"], state.get("pending")
    if D.self_mode(dep):            # directory analytics and lookups of other people are for the IAM team
        if state.get("via") == "reask" and pending:
            return {"blocks": A._reask(pending), "source": SOURCE["memory"], "trace": _step(state, "directory", t0, reask=True)}
        return {"blocks": _self_help("I can only help with your own access here."), "source": SOURCE["agent"],
                "trace": _step(state, "directory", t0, outcome="self_service_help")}
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


async def lifecycle(state: ChatState) -> dict:
    t0, dep, A = time.perf_counter(), D.current(), _assistant()
    res, text_in = state["nlu"], state["text"]
    label, s = res["intent"]["label"], res["slots"]
    ctx: dict = {}

    def out(blocks, route="end", **extra):
        return {"blocks": blocks, "route": route, "source": SOURCE["agent"], "pending": ctx.get("pending"),
                "last_person": ctx.get("person") or state.get("last_person"),
                "trace": _step(state, "lifecycle", t0, intent=label, **{k: v for k, v in extra.items() if k in ("tool", "decision", "error", "outcome")}),
                **{k: v for k, v in extra.items() if k == "plan"}}

    if D.self_mode(dep):
        if label == "JOINER":
            return out(_self_help("New starters are onboarded by HR or the IAM team."), outcome="self_service_help")
        if not dep.self_identity:
            return out([narrator.text("Your login isn't linked to an identity in the directory yet (no active identity uses your "
                                      "e-mail address), so I can't look up or change access for you. Please contact the IAM team.")],
                       outcome="self_unlinked")
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
        if D.self_mode(dep) and str(who.id) != dep.self_identity["id"]:
            return out(_self_help("You can only ask about or change your own access."), outcome="self_only")
        ctx["person"] = {"employee_id": who.employee_id, "name": who.full_name}

        who_name = who.full_name
        card = await directory.identity_card(db, who)          # before the gateway: a blocked call rolls back and expires ORM objects
        slots, dropped = quarantine(label, s, nlu.catalogue())   # the planner sees typed slots only, never the text
        blocks += _dropped_blocks(dropped)
        call = planner.plan_call(slots, who.id, plan_id=uuid.uuid4().hex)
        self_request = (D.self_mode(dep) and dep.actor.can("self:request") and call.tool == "modify_user_access"
                        and call.args.get("change") in ("access_request", "access_revocation"))
        if REGISTRY[call.tool].kind == "write" and not dep.actor.can("identities:write") and not self_request:
            # a role that can't make this change is not an attack: explain, don't send it to the gateway (which would block + audit)
            msg = ("Department moves and offboarding are requested by your manager or HR, not through self-service."
                   if D.self_mode(dep) else "Your role can review this but not submit it. Ask an IAM administrator to make the change.")
            return out(blocks + card + [narrator.text(msg)], tool=call.tool, outcome="read_only_role")
        cap = dep.cap.narrowed(targets={str(who.id)})          # this turn may only touch the person it resolved
        result = (await ActionGateway().run(_gateway_ctx(db, dep, text_in, cap), call)).model_dump(mode="json")

    if not result["ok"]:
        return out(blocks + card + narrator.error_blocks(result), tool=call.tool, error=result["error"], outcome="error")
    if label == "ACCESS_STATUS_QUERY":
        what = ", ".join((s.get("applications") or []) + (s.get("access_roles") or []))
        access = result["data"]["access"] or ["No matching active or pending access."]
        lead = await _summarised([], {"note": "this answer only looked up data; nothing was requested or changed",
                                      "person": who_name, "filter": what or None, "current_access": access})
        return out(lead + card + [narrator.head(f"Current access to {what}" if what else "Current access"), narrator.bullets(access)],
                   tool=call.tool, outcome="read")

    data = result["data"]
    src = s.get("source_department")
    if label == "MOVER" and src and data.get("from_department") and src.lower() != data["from_department"].lower():
        blocks.append(narrator.text(f"Heads-up: the directory has {who_name} in {data['from_department']}, not {src}."))
    blocks = await _summarised(blocks, {"request": label.lower(), "person": who_name, "decision": result["decision"],
                                        "reasons": result["reasons"], "from_department": data.get("from_department"),
                                        "to_department": data.get("to_department"), "add": [a["name"] for a in data.get("add") or []],
                                        "remove": data.get("remove"), "questions": data.get("questions"),
                                        "effective_date": data.get("effective_date")})
    blocks += card + narrator.preview_blocks(result)
    if data.get("choices"):
        c = data["choices"][0]
        ctx["pending"] = {"label": label, "slots": s, "ask": c["ask"], "app": c.get("app"), "options": c["options"],
                          "question": (data.get("questions") or ["Which one?"])[0]}
    if result["decision"] in (policy.AUTO, policy.APPROVAL):
        can_write = dep.actor.can("identities:write") or self_request
        blocks += narrator.confirm_blocks(call.plan_id, result["decision"], data.get("effective_date"), can_write)
        if can_write:
            return out(blocks, route="confirm", tool=call.tool, decision=result["decision"],
                       plan={"plan_id": call.plan_id, "steps": [call.model_dump(mode="json")], "decisions": [result["decision"]]})
    return out(blocks, tool=call.tool, decision=result["decision"])


async def multi(state: ChatState) -> dict:
    """Compound request: one ActionPlan, every step previewed through the gateway, then cross-step verification, then ONE confirm."""
    t0, dep = time.perf_counter(), D.current()
    clauses, text_in = state["clauses"], state["text"]
    plan_id, steps, previews, blocks = uuid.uuid4().hex, [], [], [narrator.head(f"Plan: {len(clauses)} changes")]

    def done(extra_blocks, **kw):
        return {"blocks": blocks + extra_blocks, "route": kw.pop("route", "end"), "source": SOURCE["agent"], "pending": None,
                "trace": _step(state, "multi", t0, steps=len(steps), **{k: v for k, v in kw.items() if k != "plan"}),
                **({"plan": kw["plan"]} if "plan" in kw else {})}

    if not dep.actor.can("identities:write"):
        msg = ("Please send your changes one at a time, for example “I need access to GitHub”." if D.self_mode(dep)
               else "Your role can review access but not submit changes. Ask an IAM administrator to make them.")
        return done([narrator.text(msg)], outcome="read_only_role")
    async with dep.sessionmaker() as db:
        resolved = []
        for i, res in enumerate(clauses, 1):
            label, s = res["intent"]["label"], res["slots"]
            matches = await directory.resolve_identities(db, dep.actor, s)
            if len(matches) != 1:
                who = s.get("person") or s.get("employee_id")
                return done([narrator.text(f"Step {i}: " + (f"I couldn't find “{who}”." if not matches else f"“{who}” matches {len(matches)} people.")
                                           + " Please send the changes one at a time.")], outcome="unresolved_step")
            slots, dropped = quarantine(label, s, nlu.catalogue())
            resolved.append((matches[0].id, matches[0].full_name, planner.plan_call(slots, matches[0].id, plan_id=plan_id), dropped))
        cap = dep.cap.narrowed(targets={str(r[0]) for r in resolved})     # the plan may only touch the people it named
        for i, (iid, name, call, dropped) in enumerate(resolved, 1):
            r = (await ActionGateway().run(_gateway_ctx(db, dep, text_in, cap), call)).model_dump(mode="json")
            blocks += [narrator.head(f"Step {i}: {name}")] + _dropped_blocks(dropped)
            if not r["ok"]:
                return done(narrator.error_blocks(r), outcome="error", error=r["error"])
            blocks += narrator.preview_blocks(r)[1:] if r["decision"] in (policy.AUTO, policy.APPROVAL) else narrator.preview_blocks(r)
            blocks.append(narrator.text(f"Step decision: {r['decision']}"))
            steps.append(call)
            previews.append(r)
        # a later pure-removal step already covered by an earlier step (a move removes old-department access) would become a
        # no-op at commit time and stop the plan, so drop it now and say why
        keep_i: list[int] = []
        removed_by: dict[str, set] = {}
        for i, (c, r) in enumerate(zip(steps, previews)):
            d, pid = r["data"] or {}, c.args["identity_id"]
            rem = set(d.get("remove_ids") or [])
            if r["decision"] == policy.NOOP:
                blocks.append(narrator.text(f"Step {i + 1} changes nothing, so it was dropped from the plan."))
                continue
            if not d.get("add") and rem and rem <= removed_by.get(pid, set()):
                blocks.append(narrator.text(f"Step {i + 1} is already covered by an earlier step, so it was dropped from the plan."))
                continue
            removed_by.setdefault(pid, set()).update(rem)
            keep_i.append(i)
        steps, previews = [steps[i] for i in keep_i], [previews[i] for i in keep_i]
        if not steps:
            return done([narrator.text("None of these changes would change anything, so there is nothing to submit.")], outcome="noop")
        held = {str(iid): {str(x) for x in (await policy._held(db, iid))} for iid, *_ in resolved}
        sod = await policy._sod_policies(db)
    forced, why = planner.verify_plan(
        [{"identity_id": c.args["identity_id"], "kind": (r["data"] or {}).get("kind"), "adds": [a["id"] for a in r["data"].get("add") or []],
          "removes": r["data"].get("remove_ids") or []} for c, r in zip(steps, previews)], held, sod)
    decisions = [r["decision"] for r in previews]
    overall = forced or max(decisions, key=lambda d: policy._SEVERITY[d])
    blocks += [narrator.head(narrator.DECISION_TITLE.get(overall, "Result"))] + ([narrator.bullets(why)] if why else [])
    if overall not in (policy.AUTO, policy.APPROVAL):
        return done([narrator.text("Nothing was submitted. Fix the step above, or send the changes separately.")], outcome=overall)
    plan = {"plan_id": plan_id, "steps": [c.model_dump(mode="json") for c in steps], "decisions": decisions}
    blocks[:0] = await _summarised([], {"plan": [{"person": n, "tool": c.tool, "decision": r["decision"],
                                                  "to_department": (r["data"] or {}).get("to_department"),
                                                  "add": [a["name"] for a in (r["data"] or {}).get("add") or []],
                                                  "remove": (r["data"] or {}).get("remove")}
                                                 for (_, n, c, _d), r in zip([x for x in resolved if x[2] in steps], previews)],
                                        "overall_decision": overall, "verifier": why})
    return done(narrator.confirm_blocks(plan_id, overall, None, True), route="confirm", plan=plan, outcome="awaiting_confirmation",
                decision=overall)


async def investigate(state: ChatState) -> dict:
    """'Why does X have Y?': read-only evidence through the gateway (explain_entitlement_origin)."""
    t0, dep = time.perf_counter(), D.current()
    who, what = state["investigation"]["who"], state["investigation"]["what"]
    cat = nlu.catalogue()
    ent = next((e for e in cat.get("entitlements") or [] if e.lower() == what.lower()), None)
    app_ = None if ent else next((a for a in cat.get("applications") or [] if a.lower() == what.lower()
                                  or a.lower() in what.lower().split()), None)

    def done(blocks, **kw):
        return {"blocks": blocks, "route": "end", "source": SOURCE["agent"], "trace": _step(state, "investigate", t0, **kw)}

    if not (ent or app_):
        return done([narrator.text(f"I don't know an application or entitlement called “{what[:80]}”.")], outcome="unknown_entitlement")
    async with dep.sessionmaker() as db:
        slots, _ = quarantine("ACCESS_STATUS_QUERY", {"person": who} if not _is_employee_id(who) else {"employee_id": who}, cat)
        matches = await directory.resolve_identities(db, dep.actor, {"person": slots.person, "employee_id": slots.employee_id})
        if D.self_mode(dep):          # self-service: "why do I have X" (or their own name) only
            matches = [m for m in matches if dep.self_identity and str(m.id) == dep.self_identity["id"]] if matches else []
            if not matches and dep.self_identity and who.lower() in ("i", "me", "my", "myself"):
                matches = [await db.get(Identity, uuid.UUID(dep.self_identity["id"]))]
            if not matches:
                return done(_self_help("You can only ask about your own access."), outcome="self_only")
        if len(matches) != 1:
            return done([narrator.text(f"I couldn't find “{who[:80]}”." if not matches else f"“{who[:80]}” matches {len(matches)} people; "
                                       "add a surname or employee ID.")], outcome="unresolved_person")
        call = ToolCall(tool="explain_entitlement_origin", args={"identity_id": str(matches[0].id), "entitlement": ent, "application": app_},
                        proposed_by="investigator")
        r = (await ActionGateway().run(_gateway_ctx(db, dep, state["text"], dep.cap.narrowed(targets={str(matches[0].id)})), call)).model_dump(mode="json")
    if not r["ok"]:
        return done(narrator.error_blocks(r), outcome="error", error=r["error"])
    blocks = narrator.origin_blocks(r["data"])
    advice = await llm_agents.investigate(dep.llm, r["data"]) if dep.llm and r["data"]["entitlements"] else None
    if advice:
        blocks += narrator.advice_blocks("Reviewer", advice)
    return done(blocks, outcome="read", tool=call.tool, found=len(r["data"]["entitlements"]),
                recommendation=advice["recommendation"] if advice else None)


async def copilot(state: ChatState) -> dict:
    """Approver Copilot: deterministic facts about REQ-n (read tool) + an LLM recommendation. Advice only; it never decides."""
    t0, dep, ref = time.perf_counter(), D.current(), state["copilot_ref"]

    def done(blocks, **kw):
        return {"blocks": blocks, "route": "end", "source": SOURCE["agent"], "trace": _step(state, "copilot", t0, **kw)}

    if not dep.actor.can("approvals:read"):
        return done(_self_help("Request briefings are for approvers."), outcome="self_only")

    call = ToolCall(tool="get_request_details", args={"ref_no": ref}, proposed_by="copilot")
    async with dep.sessionmaker() as db:
        r = (await ActionGateway().run(_gateway_ctx(db, dep, state["text"]), call)).model_dump(mode="json")
    if not r["ok"]:
        return done(narrator.error_blocks(r), outcome="error", error=r["error"])
    f = r["data"]
    blocks = [narrator.head(f"{f['ref']}: {f['type']} for {f['identity']['name']} ({f['status']})"), narrator.kv([
        ("Person risk", f"{f['identity']['risk_score']}/100 ({f['identity']['risk_level']})"),
        ("Department", " → ".join(x for x in (f["from_department"], f["to_department"]) if x) or None),
        ("Requested by", f["requested_by"]), ("Justification", f"“{f['justification']}”" if f["justification"] else None),
        ("Changes", "; ".join(f"{c['action']} {c['entitlement']} ({c['risk_level']}{', outside baseline' if not c['in_baseline'] else ''})"
                              for c in f["changes"]) or "none"),
        ("SoD conflicts", ", ".join(f["separation_of_duties_conflicts"]) or "none"),
        ("Requester flags", "; ".join(f["requester_flags"]) or "none"),
        ("Approval", f"{f['approval']['status']} ({f['approval']['priority']})" if f["approval"] else None)])]
    advice = await llm_agents.brief(dep.llm, f) if dep.llm else None
    if advice:
        blocks += narrator.advice_blocks("Copilot", advice)
    if f["approval"] and f["approval"]["status"] == "pending":
        blocks.append({"type": "action", "label": "Open approvals queue", "action": "nav:approvals"})
    return done(blocks, outcome="brief", recommendation=advice["recommendation"] if advice else None)


def _is_employee_id(v: str) -> bool:
    return bool(re.fullmatch(r"(?i)emp-[0-9a-f]{4,10}", v.strip()))


async def confirm(state: ChatState) -> dict:
    """Pause for the human. Resume value: {"confirm": bool, "call_id": <plan_id>}. Steps commit in order through the gateway,
    each re-checked by the policy engine with the decision the person saw; the first failure stops the rest."""
    plan = state["plan"]
    answer = interrupt({"call_id": plan["plan_id"], "steps": [st["tool"] for st in plan["steps"]], "decisions": plan["decisions"]})
    t0, dep = time.perf_counter(), D.current()
    if not isinstance(answer, dict) or answer.get("call_id") != plan["plan_id"]:
        return {"blocks": [narrator.text("That confirmation is out of date, so nothing was changed. Please review the latest plan.")],
                "plan": None, "trace": _step(state, "confirm", t0, outcome="stale")}
    if not answer.get("confirm"):
        return {"blocks": [narrator.text("Cancelled. Nothing was changed.")], "plan": None, "trace": _step(state, "confirm", t0, outcome="cancelled")}
    blocks, results, multi = [], [], len(plan["steps"]) > 1
    for i, (raw, decision) in enumerate(zip(plan["steps"], plan["decisions"]), 1):
        tc = ToolCall.model_validate(raw)
        async with dep.sessionmaker() as db:
            r = (await ActionGateway().run(_gateway_ctx(db, dep, state.get("text") or ""), tc, mode="commit",
                                           expected_decision=decision)).model_dump(mode="json")
        results.append(r)
        if multi:
            blocks.append(narrator.head(f"Step {i}"))
        if not r["ok"]:
            blocks += narrator.error_blocks(r)
            if i < len(plan["steps"]):
                blocks.append(narrator.text(f"Stopped here: the remaining {len(plan['steps']) - i} step(s) were not submitted."
                                            + (" Earlier steps were submitted." if i > 1 else "")))
            break
        blocks += narrator.done_blocks(r)
    if any(r["ok"] for r in results) and dep.request is not None:
        await invalidate(dep.request)
    last = results[-1]
    blocks = await _summarised(blocks, {"submitted": [{"ref": r.get("audit_ref"), "decision": r.get("decision"),
                                                      "applied": (r.get("data") or {}).get("applied")} for r in results if r["ok"]],
                                        "failed": [r.get("error") for r in results if not r["ok"]]})
    return {"blocks": blocks, "result": last, "plan": None, "source": SOURCE["agent"],
            "trace": _step(state, "confirm", t0, outcome="committed" if all(r["ok"] for r in results) else last["error"],
                           steps=len(results), refs=[r.get("audit_ref") for r in results if r["ok"]])}


def _route(state: ChatState) -> str:
    return state.get("route") or "end"


def build(checkpointer: Any):
    g = StateGraph(ChatState)
    g.add_node("sentinel", sentinel)
    g.add_node("understand", understand)
    g.add_node("directory", directory_answer)
    g.add_node("lifecycle", lifecycle)
    g.add_node("multi", multi)
    g.add_node("investigate", investigate)
    g.add_node("copilot", copilot)
    g.add_node("confirm", confirm)
    g.add_edge(START, "sentinel")
    g.add_conditional_edges("sentinel", _route, {"understand": "understand", "end": END})
    g.add_conditional_edges("understand", _route, {"lifecycle": "lifecycle", "directory": "directory", "multi": "multi",
                                                   "investigate": "investigate", "copilot": "copilot", "end": END})
    g.add_conditional_edges("multi", _route, {"confirm": "confirm", "end": END})
    g.add_edge("investigate", END)
    g.add_edge("copilot", END)
    g.add_edge("directory", END)
    g.add_conditional_edges("lifecycle", _route, {"confirm": "confirm", "end": END})
    g.add_edge("confirm", END)
    return g.compile(checkpointer=checkpointer)
