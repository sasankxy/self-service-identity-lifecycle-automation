"""Capability tokens: what an agent may do on behalf of one human, for one turn.

The token is minted by the API layer from the authenticated Principal (never from model output) and is the ceiling for every
tool call in that turn: an agent can never do more than the person it acts for, and a prompt-injected "call deprovision_user"
fails here if the turn was only granted read tools. Tokens are HMAC-signed so they can also cross a process boundary (MCP server)
without being forgeable, and they expire after `ttl_s` seconds.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field

from app.services.accounts import Principal

READ_TOOLS = frozenset({"inspect_user_access", "search_identities", "get_identity_profile", "get_department_baseline",
                        "peer_access_stats", "list_pending_requests", "explain_entitlement_origin",
                        "get_request_details"})
WRITE_TOOLS = frozenset({"provision_user", "modify_user_access", "deprovision_user"})
SELF_READ_TOOLS = frozenset({"inspect_user_access", "explain_entitlement_origin"})
SELF_WRITE_TOOLS = frozenset({"modify_user_access"})          # access_request / access_revocation only (enforced by the gateway)
ANY = "*"                     # target wildcard: any identity the actor's permissions allow


class CapabilityError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Capability:
    actor_id: str
    actor_email: str
    permissions: frozenset[str]
    tools: frozenset[str]
    targets: frozenset[str]   # identity ids (str) or {ANY}
    exp: float
    nonce: str = field(default_factory=lambda: secrets.token_hex(8))

    def allows_tool(self, tool: str) -> bool:
        return tool in self.tools

    def allows_target(self, identity_id) -> bool:
        return ANY in self.targets or str(identity_id) in self.targets

    def expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.exp

    def narrowed(self, *, tools: set[str] | None = None, targets: set[str] | None = None) -> Capability:
        """A sub-capability (never wider): used to hand a sub-agent only what it needs."""
        t = self.tools & frozenset(tools) if tools is not None else self.tools
        g = self.targets if targets is None else (frozenset(targets) if ANY in self.targets else self.targets & frozenset(targets))
        return Capability(self.actor_id, self.actor_email, self.permissions, t, g, self.exp)


def tools_for(p: Principal) -> frozenset[str]:
    """The tool ceiling implied by the person's portal permissions."""
    out: set[str] = set()
    if p.can("identities:read"):
        out |= READ_TOOLS
    else:                                        # self-service: own identity only (the API narrows targets to it)
        if p.can("self:read"):
            out |= SELF_READ_TOOLS
        if p.can("self:request"):
            out |= SELF_WRITE_TOOLS
    if p.can("identities:write"):
        out |= WRITE_TOOLS
    return frozenset(out)


def mint(p: Principal, *, ttl_s: int = 300, tools: set[str] | None = None, targets: set[str] | None = None) -> Capability:
    ceiling = tools_for(p)
    return Capability(actor_id=p.id, actor_email=p.email, permissions=frozenset(p.permissions),
                      tools=ceiling & frozenset(tools) if tools is not None else ceiling,
                      targets=frozenset(targets) if targets is not None else frozenset({ANY}), exp=time.time() + ttl_s)


# ─────────────────────────── signed wire format (for the MCP server / cross-process use)
def _key(secret: str) -> bytes:
    if len(secret) < 16:
        raise CapabilityError("misconfigured", "Capability signing secret is missing or too short.")
    return hmac.new(secret.encode(), b"identityos-agent-capability-v1", hashlib.sha256).digest()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def encode(cap: Capability, secret: str) -> str:
    body = json.dumps({"a": cap.actor_id, "e": cap.actor_email, "p": sorted(cap.permissions), "t": sorted(cap.tools),
                       "g": sorted(cap.targets), "x": cap.exp, "n": cap.nonce}, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(_key(secret), body, hashlib.sha256).digest()
    return f"{_b64(body)}.{_b64(sig)}"


def decode(token: str, secret: str, now: float | None = None) -> Capability:
    try:
        body_s, sig_s = token.split(".", 1)
        body, sig = _unb64(body_s), _unb64(sig_s)
    except Exception as e:  # noqa: BLE001
        raise CapabilityError("malformed", "Malformed capability token.") from e
    if not hmac.compare_digest(sig, hmac.new(_key(secret), body, hashlib.sha256).digest()):
        raise CapabilityError("bad_signature", "Capability token signature is invalid.")
    d = json.loads(body)
    cap = Capability(d["a"], d["e"], frozenset(d["p"]), frozenset(d["t"]), frozenset(d["g"]), float(d["x"]), d["n"])
    if cap.expired(now):
        raise CapabilityError("expired", "Capability token has expired.")
    return cap
