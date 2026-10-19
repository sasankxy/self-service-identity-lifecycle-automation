"""Short-term conversation memory for the assistant (Redis, per user + per chat session, expires after 20 minutes).

What is remembered, and nothing more:
  pending      the question the assistant just asked ("which AWS entitlement?"), the partly-filled request it belongs to
               (intent + slots) and the allowed answers. The next message is first tried as an ANSWER to that question.
  last_person  the employee most recently shown, so "move him to Finance" can be resolved.

Safety properties (all enforced by the caller in api/v1/assistant.py):
  * the key contains the authenticated user id, so one user can never read or continue another user's chat;
  * an answer only fills a slot; the request is then re-planned from scratch by the deterministic policy engine;
  * typing "yes"/"confirm" never executes anything. Execution still needs the Confirm button (POST /assistant/execute);
  * if Redis is down the assistant simply behaves statelessly (that is also what happens when no session id is sent).
"""
from __future__ import annotations

import difflib
import json
import logging
import re

from redis.exceptions import RedisError

log = logging.getLogger("identityos.memory")
TTL_SECONDS = 20 * 60
SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{1,59}$")
CANCEL = {"cancel", "never mind", "nevermind", "forget it", "stop", "abort", "no", "nope", "skip", "drop it", "ignore"}

_ORD = {"first": 0, "1st": 0, "1": 0, "second": 1, "2nd": 1, "2": 1, "third": 2, "3rd": 2, "3": 2, "fourth": 3, "4th": 3,
        "4": 3, "fifth": 4, "5th": 4, "5": 4, "sixth": 5, "6th": 5, "6": 5, "last": -1}
_FILLER = {"the", "option", "number", "no", "choice", "please", "use", "pick", "choose", "go", "with", "for", "i", "want", "need",
           "take", "select", "give", "me", "my", "just", "only", "it", "that", "this", "one", "a", "an", "to", "of", "lets", "let", "s", "ok", "okay", "yes", "then"}


def key(user_id: str, session_id: str) -> str:
    return f"assistant:session:{user_id}:{session_id}"


async def load(redis, user_id: str, session_id: str | None) -> dict:
    if not session_id or not SESSION_RE.match(session_id):
        return {}
    try:
        raw = await redis.get(key(user_id, session_id))
        return json.loads(raw) if raw else {}
    except (RedisError, ValueError):
        log.warning("assistant memory unavailable; continuing statelessly")
        return {}


async def save(redis, user_id: str, session_id: str | None, state: dict) -> None:
    if not session_id or not SESSION_RE.match(session_id):
        return
    try:
        k = key(user_id, session_id)
        if state.get("pending") or state.get("last_person"):
            await redis.set(k, json.dumps(state), ex=TTL_SECONDS)
        else:
            await redis.delete(k)
    except RedisError:
        log.warning("assistant memory write failed")


def tokens(s: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", (s or "").lower())


def is_cancel(text: str) -> bool:
    return " ".join(tokens(text)) in CANCEL


def _ordinal(text: str, n: int) -> int | None:
    rest = [t for t in tokens(text) if t not in _FILLER or t in _ORD]
    if len(rest) == 1 and rest[0] in _ORD:
        i = _ORD[rest[0]]
        i = n - 1 if i == -1 else i
        return i if 0 <= i < n else None
    return None


def _forms(o: dict) -> list[list[str]]:
    return [tokens(x) for x in [o.get("label", ""), o.get("value", ""), *o.get("aliases", [])] if x]


def _prefix_subset(reply: list[str], form: list[str]) -> bool:
    """every reply word equals or (3+ letters) starts a word of the option: 'admin' -> 'administratoraccess'."""
    return bool(reply) and all(any(f == t or (len(t) >= 3 and f.startswith(t)) for f in form) for t in reply)


def match_option(options: list[dict], text: str) -> tuple[str, list[dict]]:
    """('one', [opt]) | ('many', [opts]) | ('none', [])"""
    if not options:
        return "none", []
    i = _ordinal(text, len(options))
    if i is not None:
        return "one", [options[i]]
    reply = [t for t in tokens(text) if t not in _FILLER]
    joined = " ".join(tokens(text))
    exact = [o for o in options if any(joined == " ".join(f) for f in _forms(o))]
    if len(exact) == 1:
        return "one", exact
    hits = [o for o in options if any(_prefix_subset(reply, f) for f in _forms(o))]
    if not hits:   # the option's own words all appear in the reply ("the finance team")
        hits = [o for o in options if any(f and set(f) <= set(tokens(text)) for f in _forms(o))]
    if len(hits) == 1:
        return "one", hits
    if len(hits) > 1:
        return "many", hits
    names = {" ".join(f): o for o in options for f in _forms(o)}
    close = difflib.get_close_matches(joined, list(names), n=2, cutoff=0.82)
    if len({id(names[c]) for c in close}) == 1:
        return "one", [names[close[0]]]
    return "none", []


def apply_answer(pending: dict, text: str) -> tuple[str, list[dict] | dict]:
    """Interpret `text` as the answer to `pending`.  ('one', new_slots) | ('many', [options]) | ('none', [])"""
    options = pending.get("options") or []
    if options:
        kind, hit = match_option(options, text)
        return ("one", fill(pending, hit[0])) if kind == "one" else (kind, hit)
    if pending.get("ask") == "person" and NAME_RE.match(text.strip()):
        return "one", fill(pending, {"value": text.strip(), "label": text.strip()})
    return "none", []


def fill(pending: dict, opt: dict) -> dict:
    s = {k: (list(v) if isinstance(v, list) else v) for k, v in (pending.get("slots") or {}).items()}
    ask = pending["ask"]
    if ask == "person":
        s["person"], s["employee_id"], s["subject_reference"] = opt.get("label") or opt["value"], opt.get("employee_id"), None
    elif ask == "applications":
        s["applications"] = list(dict.fromkeys([*(s.get("applications") or []), opt["value"]]))
    elif ask == "access_roles":
        s["access_roles"] = list(dict.fromkeys([*(s.get("access_roles") or []), opt["value"]]))
        if pending.get("app"):          # the vague application ("AWS") has now been made specific
            s["applications"] = [a for a in (s.get("applications") or []) if a.lower() != pending["app"].lower()]
    else:                               # target_department, access_profile
        s[ask] = opt["value"]
    return s
