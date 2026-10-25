"""LLM runtime for the agents: one OpenAI-compatible client (Groq by default), a model per agent role, strict JSON output,
and hard operational limits.

Every agent that uses a model goes through this module:
  * per-role model routing     reasoning roles -> AGENT_MODEL_DEFAULT, fast roles -> AGENT_MODEL_FAST, the sentinel -> a
                               dedicated prompt-injection classifier (AGENT_MODEL_GUARD); AGENT_MODELS="role=model,..." overrides
  * schema-constrained output  `response_format: json_schema (strict)`; callers still re-validate everything
  * per-turn budget            at most AGENT_LLM_MAX_CALLS model calls per chat turn (stops runaway loops and cost)
  * timeout + circuit breaker  after 3 consecutive failures (timeouts, 429s) models are skipped for 60 s
  * trace                      each call (role, model, ms, ok/error) is returned with the turn for explainability
  * graceful degradation       every caller has a deterministic fallback; no model == today's rule-based behaviour

A model's output is never executed. Agents use it to understand, decompose, judge or word things; tool calls are still built by
the planner from quarantined slots and executed only by the Action Gateway.
"""
from __future__ import annotations

import contextvars
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

log = logging.getLogger("identityos.agent.llm")

ROLES = ("sentinel", "extractor", "planner", "narrator", "investigator", "copilot")
FAST_ROLES = {"narrator"}


@dataclass
class TurnBudget:
    max_calls: int
    calls: list[dict] = field(default_factory=list)

    @property
    def exhausted(self) -> bool:
        return sum(1 for c in self.calls if c.get("error") not in ("budget_exhausted", "circuit_open")) >= self.max_calls


_budget: contextvars.ContextVar[TurnBudget | None] = contextvars.ContextVar("agent_llm_budget", default=None)


def start_turn(max_calls: int) -> TurnBudget:
    b = TurnBudget(max_calls)
    _budget.set(b)
    return b


def turn_calls() -> list[dict]:
    b = _budget.get()
    return list(b.calls) if b else []


class CircuitBreaker:
    def __init__(self, threshold: int = 3, cooldown_s: float = 60.0):
        self.threshold, self.cooldown_s, self.failures, self.open_until = threshold, cooldown_s, 0, 0.0

    @property
    def open(self) -> bool:
        return time.monotonic() < self.open_until

    def record(self, ok: bool) -> None:
        if ok:
            self.failures = 0
            return
        self.failures += 1
        if self.failures >= self.threshold:
            self.open_until, self.failures = time.monotonic() + self.cooldown_s, 0


def parse_models(spec: str, default: str, fast: str, guard: str) -> dict[str, str]:
    models = {r: (fast if r in FAST_ROLES else default) for r in ROLES}
    models["sentinel"] = guard
    for part in (spec or "").split(","):
        if "=" in part:
            role, model = (x.strip() for x in part.split("=", 1))
            if role in models and model:
                models[role] = model
    return models


class LLM:
    """Base client: budgeting, breaker and tracing. Subclasses implement `_chat`."""

    def __init__(self, models: dict[str, str], timeout_s: float = 20.0):
        self.models, self.timeout_s, self.breaker = models, timeout_s, CircuitBreaker()

    async def _chat(self, model: str, messages: list[dict], response_format: dict | None, temperature: float, max_tokens: int) -> str:
        raise NotImplementedError

    async def _call(self, role: str, messages: list[dict], response_format: dict | None, temperature: float, max_tokens: int) -> str | None:
        model, budget, t0 = self.models.get(role), _budget.get(), time.perf_counter()
        if not model:
            return None
        entry: dict = {"role": role, "model": model, "ok": False}
        try:
            if budget is not None and budget.exhausted:
                entry["error"] = "budget_exhausted"
                return None
            if self.breaker.open:
                entry["error"] = "circuit_open"
                return None
            out = await self._chat(model, messages, response_format, temperature, max_tokens)
            entry["ok"] = True
            self.breaker.record(True)
            return out
        except Exception as e:  # noqa: BLE001 - any model failure degrades to the deterministic path
            entry["error"] = type(e).__name__ if not isinstance(e, httpx.HTTPStatusError) else f"http_{e.response.status_code}"
            self.breaker.record(False)
            log.warning("LLM %s (%s) failed: %s", role, model, entry["error"])
            return None
        finally:
            entry["ms"] = round((time.perf_counter() - t0) * 1000)
            if budget is not None:
                budget.calls.append(entry)

    async def json(self, role: str, system: str, user: str, schema: dict, *, temperature: float = 0.0,
                   max_tokens: int = 600) -> dict | None:
        """Schema-constrained JSON object, or None on any failure. Never raises."""
        raw = await self._call(role, [{"role": "system", "content": system}, {"role": "user", "content": user}],
                               {"type": "json_schema", "json_schema": {"name": role, "strict": True, "schema": schema}},
                               temperature, max_tokens)
        if raw is None:
            return None
        try:
            out = json.loads(raw)
            return out if isinstance(out, dict) else None
        except ValueError:
            log.warning("LLM %s returned non-JSON output", role)
            return None

    async def injection_score(self, text: str) -> float | None:
        """Probability that `text` is a prompt-injection / jailbreak (dedicated classifier model), or None if unavailable."""
        raw = await self._call("sentinel", [{"role": "user", "content": text[:2000]}], None, 0.0, 8)
        try:
            return max(0.0, min(1.0, float(raw))) if raw is not None else None
        except ValueError:
            return None


class OpenAICompatLLM(LLM):
    """Any OpenAI-compatible chat-completions API (Groq, OpenRouter, Gemini's compatibility endpoint, a local vLLM...)."""

    def __init__(self, base_url: str, api_key: str, models: dict[str, str], timeout_s: float = 20.0):
        super().__init__(models, timeout_s)
        self._http = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout_s,
                                       headers={"Authorization": f"Bearer {api_key}"})

    async def _chat(self, model, messages, response_format, temperature, max_tokens) -> str:
        body: dict[str, Any] = {"model": model, "messages": messages, "temperature": temperature, "max_completion_tokens": max_tokens}
        if response_format:
            body["response_format"] = response_format
        if model.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = "low"       # reasoning tokens count against max_completion_tokens; keep them small
        r = await self._http.post("/chat/completions", json=body)
        if r.status_code >= 400:
            log.warning("LLM API %s for %s: %s", r.status_code, model, r.text[:300])
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"] or ""

    async def aclose(self) -> None:
        await self._http.aclose()


class FakeLLM(LLM):
    """Deterministic stand-in for tests: `responder(role, system, user) -> dict | float | None` (None simulates a failure)."""

    def __init__(self, responder: Callable[[str, str, str], Any], models: dict[str, str] | None = None):
        super().__init__(models or {r: f"fake-{r}" for r in ROLES})
        self.responder = responder
        self.seen: list[tuple[str, str]] = []

    async def _chat(self, model, messages, response_format, temperature, max_tokens) -> str:
        role = next(r for r, m in self.models.items() if m == model)
        system = messages[0]["content"] if len(messages) > 1 else ""
        user = messages[-1]["content"]
        self.seen.append((role, user))
        out = self.responder(role, system, user)
        if out is None:
            raise TimeoutError("fake failure")
        return str(out) if isinstance(out, (int, float)) else json.dumps(out)


def build(settings) -> LLM | None:
    if not settings.agent_llm_enabled or not settings.agent_llm_api_key:
        return None
    models = parse_models(settings.agent_models, settings.agent_model_default, settings.agent_model_fast, settings.agent_model_guard)
    return OpenAICompatLLM(settings.agent_llm_base_url, settings.agent_llm_api_key.get_secret_value(), models, settings.agent_llm_timeout_s)


def data_block(tag: str, value: Any) -> str:
    """Wrap untrusted content so prompts treat it as data. A closing tag inside the value is neutralised."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return f"<{tag}>\n{text.replace(f'</{tag}>', f'</ {tag}>')}\n</{tag}>"
