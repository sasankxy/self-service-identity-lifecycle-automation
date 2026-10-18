"""Local small-language-model fallback (Ollama, e.g. qwen2.5).

The SLM is consulted ONLY when the custom NLU engine cannot interpret a request (unknown intent, or a department
that was only described, e.g. "the team that handles invoices"). It is strictly an interpreter:

* output is constrained to a JSON schema and then re-validated here against the directory catalogue;
  anything not in the catalogue (hallucinated department/application) is discarded;
* it never grants, approves or executes anything. Its only output is a *suggested rephrasing* that the person can
  click to re-submit, which then goes through the deterministic NLU -> resolution -> policy path like any request;
* if Ollama is disabled, unreachable or slow, `interpret()` returns None and the assistant says it didn't understand.
"""
from __future__ import annotations

import json
import logging

import httpx

log = logging.getLogger("identityos.slm")

INTENTS = ["JOINER", "MOVER", "LEAVER", "ACCESS_REQUEST", "ACCESS_REVOCATION", "ACCESS_STATUS_QUERY", "UNKNOWN"]
SCHEMA = {
    "type": "object",
    "properties": {
        "intent": {"type": "string", "enum": INTENTS},
        "person": {"type": ["string", "null"]},
        "source_department": {"type": ["string", "null"]},
        "target_department": {"type": ["string", "null"]},
        "applications": {"type": "array", "items": {"type": "string"}},
        "clarification_question": {"type": ["string", "null"]},
    },
    "required": ["intent", "person", "source_department", "target_department", "applications", "clarification_question"],
}


def system_prompt(cat: dict) -> str:
    return ("You interpret identity-lifecycle requests for an IT access-management system. Reply with JSON only.\n"
            f"Allowed departments: {', '.join(cat['departments'])}.\nAllowed applications: {', '.join(cat['applications'])}.\n"
            "Rules: choose departments/applications ONLY from the allowed lists, otherwise use null / an empty list. "
            "Never invent a person; copy the name exactly as written or use null. If the request is vague (e.g. 'whatever he needs'), "
            "do not guess access: leave applications empty and write ONE short clarification_question. "
            "Intents: JOINER (new hire), MOVER (change department), LEAVER (offboarding), ACCESS_REQUEST (wants access), "
            "ACCESS_REVOCATION (remove access), ACCESS_STATUS_QUERY (asks what access exists), UNKNOWN.")


def _pick(value, allowed: list[str]) -> str | None:
    if not isinstance(value, str):
        return None
    return next((a for a in allowed if a.lower() == value.strip().lower()), None)


def sanitize(raw: dict | None, cat: dict) -> dict | None:
    """Validate the model output against the catalogue and derive a canonical rephrasing (built by us, not the model)."""
    if not isinstance(raw, dict) or raw.get("intent") not in INTENTS or raw["intent"] == "UNKNOWN" and not raw.get("clarification_question"):
        return None
    person = raw.get("person") if isinstance(raw.get("person"), str) and 0 < len(raw["person"].strip()) <= 80 else None
    src, tgt = _pick(raw.get("source_department"), cat["departments"]), _pick(raw.get("target_department"), cat["departments"])
    apps = [a for a in (_pick(x, cat["applications"]) for x in raw.get("applications") or []) if a]
    q = raw.get("clarification_question")
    q = q.strip()[:200] if isinstance(q, str) and q.strip() else None
    who, intent = (person or "").strip(), raw["intent"]
    rephrase = None
    if who:
        if intent == "JOINER" and tgt:
            rephrase = f"Onboard {who} to {tgt}"
        elif intent == "MOVER" and tgt:
            rephrase = f"Move {who}" + (f" from {src}" if src else "") + f" to {tgt}" + (f" and give them access to {', '.join(apps)}" if apps else "")
        elif intent == "ACCESS_REQUEST" and apps:
            rephrase = f"Give {who} access to {', '.join(apps)}"
        elif intent == "ACCESS_REVOCATION" and apps:
            rephrase = f"Revoke {who}'s access to {', '.join(apps)}"
        elif intent == "ACCESS_STATUS_QUERY":
            rephrase = f"What access does {who} have" + (f" to {', '.join(apps)}" if apps else "")
    if rephrase:
        q = None      # the suggestion is complete; the deterministic flow asks for anything still missing
    return {"intent": intent, "person": who or None, "source_department": src, "target_department": tgt,
            "applications": apps, "question": q, "rephrase": rephrase}


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: float = 25.0):
        self.base_url, self.model, self.timeout = base_url.rstrip("/"), model, timeout

    async def interpret(self, text: str, cat: dict) -> dict | None:
        body = {"model": self.model, "stream": False, "format": SCHEMA, "options": {"temperature": 0}, "keep_alive": "30m",
                "messages": [{"role": "system", "content": system_prompt(cat)}, {"role": "user", "content": text}]}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post(f"{self.base_url}/api/chat", json=body)
                r.raise_for_status()
                return sanitize(json.loads(r.json()["message"]["content"]), cat)
        except Exception as e:  # noqa: BLE001 - Ollama down / model missing / bad JSON: degrade, never fail the request
            # httpx timeouts have an EMPTY str(), so always log the exception type and what we were calling
            log.warning("SLM unavailable (%s at %s, model=%s): %s", type(e).__name__, self.base_url, self.model, e or "no message - likely a timeout; "
                        "the model may still be loading, raise SLM_TIMEOUT_S")
            return None


_client = None


def get_client(settings):
    """Return the configured client (or None when the SLM is disabled). Tests replace this via set_client()."""
    global _client
    if _client is None and settings.slm_enabled:
        _client = OllamaClient(settings.ollama_url, settings.ollama_model, settings.slm_timeout_s)
    return _client


def set_client(c) -> None:
    global _client
    _client = c
