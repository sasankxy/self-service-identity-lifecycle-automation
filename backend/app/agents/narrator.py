"""Narrator: turns tool results into the UI block format (the same blocks the rule-based assistant returns).

It only renders facts that are in the ToolResult (decision, reasons, the plan summary); it never adds claims of its own.
"""
from __future__ import annotations

from app.services import policy
from app.services.directory import bullets, head, kv, text

DECISION_TITLE = {policy.AUTO: "Policy decision: within policy, no approval needed", policy.APPROVAL: "Policy decision: needs a human approval",
                  policy.DENY: "Policy decision: blocked", policy.CLARIFY: "I need a bit more information", policy.NOOP: "Nothing to change"}
ERRORS = {"capability_denied": "This conversation isn't allowed to do that.", "forbidden": "Your role doesn't allow that.",
          "schema_invalid": "I couldn't turn that into a valid request.", "unknown_catalogue_value": "Something in the request isn't in the directory.",
          "unknown_tool": "That action isn't available.", "duplicate": "That request was already submitted.",
          "policy_changed": "The policy outcome changed since you reviewed it.", "not_allowed": "This request cannot be submitted.",
          "not_found": "I couldn't find that identity."}


def plan_rows(d: dict) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if d.get("kind") == "leaver" and d.get("decision") != policy.NOOP:
        rows.append(("Offboarding", "Deactivates the account and revokes all access"))
    if d.get("kind") == "mover" and d.get("to_department") and d.get("to_department") != d.get("from_department"):
        rows.append(("Department", f"{d.get('from_department') or '—'} → {d['to_department']}"))
        if d.get("access_profile"):
            rows.append(("Access profile", d["access_profile"]))
    if d.get("add"):
        rows.append(("Add access", ", ".join(f"{a['name']} ({a['risk_level']})" for a in d["add"])))
    if d.get("remove"):
        rows.append(("Remove access", ", ".join(d["remove"])))
    if d.get("keeps"):
        rows.append(("Keeps", ", ".join(d["keeps"])))
    if rows:
        rows.append(("Takes effect", d.get("effective_date") or "immediately"))
    return rows


def preview_blocks(result: dict) -> list[dict]:
    d, decision = result.get("data") or {}, result.get("decision")
    blocks = [head(DECISION_TITLE.get(decision, "Result"))]
    if d.get("questions"):
        blocks.append(bullets(d["questions"]))
    if result.get("reasons") and decision != policy.CLARIFY:
        blocks.append(bullets(list(result["reasons"])))
    rows = plan_rows(d)
    if rows:
        blocks.append(kv(rows))
    blocks += [text(n) for n in d.get("notes") or []]
    for name in d.get("profile_options") or []:
        blocks.append({"type": "action", "label": f"Use profile: {name}", "action": f"send:{name}"})
    return blocks


def confirm_blocks(call_id: str, decision: str, effective_date: str | None, can_write: bool) -> list[dict]:
    if not can_write:
        return [text("Your role can review this but not submit it.")]
    label = "Confirm and apply" if decision == policy.AUTO else "Submit for approval"
    if decision == policy.AUTO and effective_date:
        label = f"Confirm (scheduled for {effective_date})"
    return [{"type": "action", "label": label, "action": "agent-confirm", "call_id": call_id},
            {"type": "action", "label": "Cancel", "action": "agent-cancel", "call_id": call_id}]


def error_blocks(result: dict) -> list[dict]:
    code = result.get("error") or ""
    blocks = [text(ERRORS.get(code, "I couldn't complete that."))]
    reasons = [r for r in result.get("reasons") or [] if r != ERRORS.get(code)]
    if reasons:
        blocks.append(bullets(reasons[:5]))
    return blocks


def done_blocks(result: dict) -> list[dict]:
    d = result.get("data") or {}
    ref = d.get("ref") or result.get("audit_ref")
    if result.get("decision") == policy.AUTO:
        msg = f"{ref} applied." if d.get("applied") else f"{ref} approved and scheduled for {d.get('scheduled_for')}."
        note = ("No live connector is configured, so no external provisioning was executed." if d.get("applied")
                else "It will be applied on that date by the governance scheduler.")
        return [head(msg), text(note)]
    return [head(f"{ref} submitted for approval."), text("It is now in the approvals queue."),
            {"type": "action", "label": "Open approvals queue", "action": "nav:approvals"}]


ORIGIN = {"access_profile": "granted with the access profile", "request": "granted through a lifecycle request"}


def origin_blocks(d: dict) -> list[dict]:
    """Evidence for 'why does X have Y?'. Stored request text is shown as quoted data, never interpreted."""
    ents = d.get("entitlements") or []
    who = d["identity"]["name"]
    if not ents:
        return [text(f"{who} doesn't currently hold that access.")]
    blocks = [head(f"Why {who} has this access")]
    for e in ents:
        rows = [("Entitlement", f"{e['entitlement']} ({e['application']}) · {e['risk_level']} risk"),
                ("How", ORIGIN.get(e["origin"], f"granted via {e['origin']}") + (f" on {e['granted_at']}" if e.get("granted_at") else "")),
                (f"In {d.get('department') or 'department'} baseline", "yes" if e["in_department_baseline"] else "no — outside the baseline")]
        req = e.get("request")
        if req:
            rows += [("Request", f"{req['ref']} ({req['type']}, {req['status']})"), ("Requested by", req.get("requested_by")),
                     ("Approved by", req.get("approved_by")), ("Justification", f"“{req['justification']}”" if req.get("justification") else None)]
        if e.get("expires_at"):
            rows.append(("Expires", e["expires_at"]))
        blocks.append(kv([(k, v) for k, v in rows if v]))
    risky = [e for e in ents if not e["in_department_baseline"] and e["risk_level"] in ("high", "critical")]
    if risky:
        blocks.append(text("High-risk access outside the department baseline is a privilege-creep signal; consider an access review."))
    return blocks
