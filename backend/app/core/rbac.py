"""Roles and permissions (reference data). Enforced server-side via deps.require_permission."""

PERMISSIONS: dict[str, str] = {
    "self:read": "Read own profile",
    "self:request": "Request or give up access for oneself (requests for new access always go to an approver)",
    "dashboard:read": "View dashboard summaries",
    "identities:read": "View managed identities",
    "identities:write": "Create/modify managed identities",
    "approvals:read": "View approval requests",
    "approvals:decide": "Approve or reject requests",
    "risk:read": "View risk analytics",
    "audit:read": "View audit logs",
    "governance:read": "View governance data",
    "governance:manage": "Manage policies and connectors",
    "users:read": "View portal user accounts",
    "users:approve": "Approve/reject/suspend portal accounts",
    "users:manage_roles": "Change portal user roles",
    "roles:grant_privileged": "Grant or remove privileged roles",
}

_READ = ["self:read", "self:request", "dashboard:read", "identities:read", "approvals:read", "risk:read",
         "audit:read", "governance:read"]

ROLES: dict[str, dict] = {
    "super_admin": {
        "display_name": "Super Administrator",
        "description": "Full platform control, including privileged role grants.",
        "permissions": list(PERMISSIONS),
    },
    "iam_admin": {
        "display_name": "IAM Administrator",
        "description": "Operates identity lifecycle, governance and portal account approvals.",
        "permissions": _READ + ["identities:write", "approvals:decide", "governance:manage",
                                "users:read", "users:approve", "users:manage_roles"],
    },
    "approver": {
        "display_name": "Approver",
        "description": "Decides approval requests.",
        "permissions": ["self:read", "self:request", "dashboard:read", "identities:read", "approvals:read", "approvals:decide"],
    },
    "auditor": {
        "display_name": "Auditor",
        "description": "Read-only access to audit, risk and governance data.",
        "permissions": _READ,
    },
    "employee": {
        "display_name": "Employee",
        "description": "Non-privileged default role: self-service access requests through the assistant.",
        "permissions": ["self:read", "self:request"],
    },
}

DEFAULT_ROLE = "employee"
PRIVILEGED_ROLES = {"super_admin", "iam_admin"}
