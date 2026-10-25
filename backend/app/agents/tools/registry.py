"""The fixed tool whitelist (master plan §5.3, extended with read tools). Anything not in REGISTRY does not exist for an agent.

Each tool declares its argument schema, whether it reads or writes, the portal permission it needs, and which argument names the
identity it touches (so the gateway can check the capability's target scope). The JSON schemas exported by `json_schemas()` are
what LLM prompts and the MCP server advertise, and what the contract snapshot test freezes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal

from app.agents.tools import read, schemas as S, write


@dataclass(frozen=True)
class ToolSpec:
    name: str
    args: type[S.Args]
    kind: Literal["read", "write"]
    permission: str
    description: str
    target_arg: str | None = None
    run: Callable[..., Awaitable[dict]] | None = None                 # read tools
    prepare: Callable[..., Awaitable[Any]] | None = None             # write tools
    commit: Callable[..., Awaitable[dict]] | None = None
    catalogue: tuple[tuple[str, str], ...] = ()                       # (arg name, catalogue kind) checked against the live directory
    self_permission: str | None = None    # weaker permission that allows the tool ONLY on the caller's own identity


_SPECS = [
    ToolSpec("inspect_user_access", S.InspectUserAccess, "read", "self:read", "Current active and pending access of one identity, "
             "optionally filtered to applications or entitlement names.", target_arg="identity_id", run=read.inspect_user_access,
             catalogue=(("applications", "applications"), ("entitlements", "entitlements"))),
    ToolSpec("search_identities", S.SearchIdentities, "read", "identities:read", "Find identities by name, e-mail or employee id.",
             run=read.search_identities),
    ToolSpec("get_identity_profile", S.GetIdentityProfile, "read", "identities:read", "Department, access profile, manager, lifecycle "
             "state and risk of one identity.", target_arg="identity_id", run=read.get_identity_profile),
    ToolSpec("get_department_baseline", S.GetDepartmentBaseline, "read", "identities:read", "The access profiles of a department and the "
             "entitlements each one grants.", run=read.get_department_baseline, catalogue=(("department", "departments"),)),
    ToolSpec("peer_access_stats", S.PeerAccessStats, "read", "identities:read", "Entitlements commonly held by people in a department "
             "(least-privilege recommendation input).", run=read.peer_access_stats, catalogue=(("department", "departments"),)),
    ToolSpec("explain_entitlement_origin", S.ExplainEntitlementOrigin, "read", "identities:read", "Why an identity holds an "
             "entitlement: how it was granted (access profile or request), who requested and approved it, whether it is in the "
             "department baseline.", target_arg="identity_id", run=read.explain_entitlement_origin,
             catalogue=(("entitlement", "entitlements"), ("application", "applications")), self_permission="self:read"),
    ToolSpec("get_request_details", S.GetRequestDetails, "read", "approvals:read", "Everything an approver needs about one lifecycle "
             "request: changes and their risk, baseline fit, the person's risk, the requester's recent history, approval state.",
             run=read.get_request_details),
    ToolSpec("list_pending_requests", S.ListPendingRequests, "read", "approvals:read", "Lifecycle requests waiting for approval.",
             run=read.list_pending_requests),
    ToolSpec("provision_user", S.ProvisionUser, "write", "identities:write", "Onboard a new joiner with a department access profile. "
             "Always routed to an approver.", prepare=write.prepare_provision, commit=write.commit_provision,
             catalogue=(("department", "departments"),)),
    ToolSpec("modify_user_access", S.ModifyUserAccess, "write", "identities:write", "Move an identity to another department, or request or "
             "revoke access. Risk-scored by the policy engine.", target_arg="identity_id", prepare=write.prepare_modify,
             commit=write.commit_modify, catalogue=(("to_department", "departments"), ("applications", "applications"),
                                                    ("entitlements", "entitlements")), self_permission="self:request"),
    ToolSpec("deprovision_user", S.DeprovisionUser, "write", "identities:write", "Offboard an identity: deactivate and revoke all access. "
             "Always requires approval.", target_arg="identity_id", prepare=write.prepare_deprovision, commit=write.commit_deprovision),
]
REGISTRY: dict[str, ToolSpec] = {s.name: s for s in _SPECS}


def json_schemas(kind: str | None = None) -> dict[str, dict]:
    return {n: {"description": s.description, "kind": s.kind, "parameters": s.args.model_json_schema()}
            for n, s in sorted(REGISTRY.items()) if kind in (None, s.kind)}
