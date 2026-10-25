"""Per-turn runtime dependencies for graph nodes.

Graph STATE is checkpointed (Postgres), so it must hold only plain data. Live objects (DB sessionmaker, Redis, the authenticated
Principal, the capability) travel in a ContextVar set by the API handler for the duration of one graph invocation; asyncio copies
the context into every task LangGraph starts, so each node sees the deps of the request that is running it.
"""
from __future__ import annotations

import contextvars
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from app.agents import capabilities
from app.services.accounts import Principal


@dataclass
class AgentDeps:
    sessionmaker: Any
    redis: Any
    settings: Any
    request: Any
    actor: Principal
    cap: capabilities.Capability
    voice: bool = False
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)


_current: contextvars.ContextVar[AgentDeps] = contextvars.ContextVar("agent_deps")


def current() -> AgentDeps:
    return _current.get()


@contextmanager
def bound(deps: AgentDeps):
    token = _current.set(deps)
    try:
        yield deps
    finally:
        _current.reset(token)
