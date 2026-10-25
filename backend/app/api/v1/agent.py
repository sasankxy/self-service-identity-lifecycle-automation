"""Agent API: the multi-agent conversation graph (app/agents/graph.py).

  POST /agent/chat     one chat turn. May end with a pending confirmation (awaiting_confirmation=true).
  POST /agent/resume   confirm or cancel the pending action; must quote its call_id.
  GET  /agent/status   which assistant the UI should use (AGENT_MODE=legacy|graph).
  GET  /agent/trace    the per-node explainability trace of the caller's last turn in a session.

Threads are keyed by (portal user, chat session), so one user can never read or resume another user's conversation.
"""
from typing import Literal

from fastapi import APIRouter, Depends, Request
from langgraph.types import Command
from pydantic import BaseModel, Field

from app.agents import capabilities, deps as D
from app.core import csrf
from app.core.deps import require_permission
from app.core.errors import ApiError
from app.services import memory
from app.services.accounts import Principal

router = APIRouter(prefix="/agent", tags=["agent"], dependencies=[Depends(csrf.csrf_protect)])


class ChatIn(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    session_id: str = Field(min_length=8, max_length=64, pattern=memory.SESSION_RE.pattern)
    input_mode: Literal["text", "voice"] = "text"


class ResumeIn(BaseModel):
    session_id: str = Field(min_length=8, max_length=64, pattern=memory.SESSION_RE.pattern)
    call_id: str = Field(min_length=1, max_length=64)
    confirm: bool


def _graph(request: Request):
    g = getattr(request.app.state, "agent_graph", None)
    if g is None:
        raise ApiError(503, "agent_unavailable", "The agent is not available right now.")
    return g


def _config(actor: Principal, session_id: str) -> dict:
    return {"configurable": {"thread_id": f"{actor.id}:{session_id}"}}


def _deps(request: Request, actor: Principal, voice: bool = False) -> D.AgentDeps:
    return D.AgentDeps(sessionmaker=request.app.state.sessionmaker, redis=request.app.state.redis, settings=request.app.state.settings,
                       request=request, actor=actor, cap=capabilities.mint(actor), voice=voice)


def _reply(out: dict, dep: D.AgentDeps) -> dict:
    pending = out.get("__interrupt__") or []
    return {"blocks": out.get("blocks") or [], "source": out.get("source"), "trace_id": dep.trace_id,
            "awaiting_confirmation": bool(pending), "call_id": pending[0].value.get("call_id") if pending else None,
            "intent": (out.get("intent") or {}).get("action"), "trace": out.get("trace") or []}


@router.get("/status")
async def status(request: Request, _: Principal = Depends(require_permission("identities:read"))):
    return {"mode": request.app.state.settings.agent_mode, "available": getattr(request.app.state, "agent_graph", None) is not None}


@router.post("/chat")
async def chat(body: ChatIn, request: Request, actor: Principal = Depends(require_permission("identities:read"))):
    graph = _graph(request)
    with D.bound(_deps(request, actor, voice=body.input_mode == "voice")) as dep:
        out = await graph.ainvoke({"text": body.query, "voice": body.input_mode == "voice"}, _config(actor, body.session_id))
    return _reply(out, dep)


@router.post("/resume")
async def resume(body: ResumeIn, request: Request, actor: Principal = Depends(require_permission("identities:read"))):
    graph, cfg = _graph(request), _config(actor, body.session_id)
    snap = await graph.aget_state(cfg)
    waiting = [i for t in snap.tasks for i in t.interrupts]
    if not waiting:
        raise ApiError(409, "nothing_to_confirm", "There is nothing waiting for confirmation in this chat.")
    if waiting[-1].value.get("call_id") != body.call_id:
        raise ApiError(409, "stale_confirmation", "That confirmation is out of date. Please review the latest plan.")
    with D.bound(_deps(request, actor)) as dep:
        out = await graph.ainvoke(Command(resume={"confirm": body.confirm, "call_id": body.call_id}), cfg)
    return _reply(out, dep)


@router.get("/trace")
async def trace(session_id: str, request: Request, actor: Principal = Depends(require_permission("identities:read"))):
    if not memory.SESSION_RE.match(session_id):
        raise ApiError(422, "validation_error", "Invalid session id.")
    snap = await _graph(request).aget_state(_config(actor, session_id))
    v = snap.values or {}
    return {"trace": v.get("trace") or [], "intent": v.get("intent"), "awaiting_confirmation": bool(snap.next)}
