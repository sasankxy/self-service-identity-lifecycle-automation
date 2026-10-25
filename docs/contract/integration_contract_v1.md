# Integration Contract v1.2.0 — Agent layer ↔ IAM backend

**Owners:** Person A (agent layer, `backend/app/agents`) and Person B (IAM backend, policy, governance).
**Source of truth:** `backend/app/agents/contract.py` and `backend/app/agents/tools/schemas.py`. The JSON-schema snapshot
`backend/tests/agents/unit/snapshots/contract_v1.json` is enforced by `test_contract_snapshot`, so any drift fails CI.
**Change protocol (master plan §9.3):**
1. Propose the change in writing.
2. Both members acknowledge it.
3. Bump `CONTRACT_VERSION`.
4. Regenerate the snapshot (`UPDATE_CONTRACT_SNAPSHOT=1 pytest tests/agents/unit`).

Prefer additive fields over removals.

## 1. IntentV1 (Extractor → Planner)
This is a superset of master plan §5.1. Fields marked *additive* are new in v1. Every model is strict (`extra="forbid"`).

| Field | Type | Notes |
|---|---|---|
| `action` | `onboard \| modify_access \| deprovision \| inspect` | §5.1 |
| `change` | `mover \| access_request \| access_revocation \| null` | *additive*: which kind of `modify_access` |
| `user_id` | string ≤200 | Employee ID or name **as written**. Untrusted; resolved by the Resolver |
| `target_role` | string ≤160 | Access profile (the directory's role for a department) |
| `department` / `source_department` | string ≤120 | Must exist in the directory catalogue |
| `applications` / `entitlements` | string[] | *additive* |
| `effective_date` / `effective_date_text` | date / string | A date that couldn't be resolved stays as text, so the policy engine asks for a fixed date |
| `requester_id` | string | Always taken from the authenticated session, **never from text** |
| `confidence` | float 0–1 | |
| `missing_slots` | string[] | Triggers a follow-up question |
| `source` | `nlu \| slm \| memory \| governance` | *additive* |
| `self_reference` | bool | *additive*: "me / my access" |

The adapter `from_nlu()` maps the NLU pipeline's current output (`backend/nlu`) to this shape.

## 2. Tools (fixed whitelist; Person B's services sit behind them)
The plan's §5.3 tools map as follows:

| Tool | Kind | Permission | Backend path | Default decision |
|---|---|---|---|---|
| `inspect_user_access` | read | `self:read` (own identity only without `identities:read`) | `directory.entitlement_lines` | auto |
| `provision_user` | write | `identities:write` | `onboarding.create_joiner` | **always approval** |
| `modify_user_access` | write | `identities:write` | `policy.build_plan` → `lifecycle.execute_plan` | policy engine |
| `deprovision_user` | write | `identities:write` | `policy.build_plan(kind="leaver")` → `execute_plan` | **always approval** |

Additional read tools: `search_identities`, `get_identity_profile`, `get_department_baseline`, `peer_access_stats`, `list_pending_requests`,
`explain_entitlement_origin` (*v1.1*: why an identity holds access: profile vs request, requester, approver, baseline membership),
`get_request_details` (*v1.2*, `approvals:read`: approver-copilot facts for one request: changes, baseline fit, SoD, requester history).
The argument schemas are in `tools/schemas.py`, and `registry.json_schemas()` exports them for LLM prompts and the MCP server.

## 3. Execution guarantees (Action Gateway, `app/agents/gateway.py`)
Every call runs these checks in order. The first one to fail stops the call and writes an `agent.action_blocked` audit row.

| # | Check | Error code on failure |
|---|---|---|
| 1 | The tool is in the whitelist | `unknown_tool` |
| 2 | Arguments pass the strict schema | `schema_invalid` |
| 3 | The per-turn permission token belongs to this actor, is unexpired, and covers this tool and target | `capability_denied` |
| 4 | The actor's portal permission allows the tool | `forbidden` |
| 5 | Departments, applications and entitlements exist in the catalogue | `unknown_catalogue_value` |
| 6 | The policy engine (Person B) rebuilds the plan on the server; a decision supplied by the agent is ignored | — |
| 7 | The Verifier can only make the outcome stricter: self-grant → approval, self move/offboard → deny, high/critical grant → approval | — |
| 8 | Idempotency (24 h) and the identical-pending-request check | `duplicate` |
| 9 | One transaction through the existing services, plus an `agent.tool_executed` audit row (`trace_id`, `call_id`, `plan_id`) | — |

A commit requires the decision the person saw (`expected_decision`) to still hold. If the policy outcome has changed, the commit fails with `policy_changed`.

## 3a. Plans and the quarantine boundary (v1.1)
- **Quarantine:** the planner receives only a typed `Slots` object (`app/agents/security/quarantine.py`). The fields are an enum
  label, name and employee-ID patterns, catalogue-canonical department/application/entitlement values, dates, and bounded
  reason/date text that is stored as data. The planner function has no text parameter, and a test enforces that.
- **ActionPlan:** a compound request ("move X to Legal and remove their Slack access") becomes up to 3 `ToolCall`s that share
  a `plan_id`. Each step is previewed through the gateway.
- **Cross-step checks:** the steps are verified together for SoD conflicts created by the combination, and for offboarding plus
  another change for the same person. Steps that change nothing, or that an earlier step already covers, are dropped. The user
  confirms the plan once.
- **Commit:** `POST /agent/resume` quotes the `plan_id` as `call_id`. Steps commit in order, and the policy is re-checked for
  each one. The first failure stops the rest.

## 3b. LLM agents (v1.2)
| Agent | Model role | Output | Trust |
|---|---|---|---|
| Sentinel | prompt-injection classifier | probability | can only **block** (≥ `AGENT_GUARD_THRESHOLD`), after the rule check |
| Extractor | `AGENT_MODEL_DEFAULT` | IntentV1-shaped slots | used only when the NLU is unsure; output goes through the **quarantine** |
| Planner | `AGENT_MODEL_DEFAULT` | 2–3 single-intent steps | each step goes through the quarantine, the gateway and the cross-step verifier |
| Narrator | `AGENT_MODEL_FAST` | one-sentence summary | display only, grounding-checked against the facts |
| Investigator / Copilot | `AGENT_MODEL_DEFAULT` | advice (keep/review/revoke; approve/reject/more info) | advice only, grounding-checked; never decides |

No model output becomes a tool argument except through quarantine, then the planner, then the Action Gateway. Each turn has a call
budget (`AGENT_LLM_MAX_CALLS`), there's a circuit breaker, and every call is listed in `llm_calls` in the `/agent/chat` response.
With no API key the system runs fully deterministically.

## 4. ToolResult
`{call_id, tool, ok, decision: auto|approval|deny|clarify|noop|blocked, data, reasons[], error, audit_ref}`

## 5. Requests to Person B (pending sign-off)
- `approvals._decide`: block self-approval (`requested_by == actor.id` → 403).
- `approvals._decide`: write an outbox event after each decision, so the agent can tell the requester the outcome.
- Audit log hash chain (`prev_hash`, migration 0004).
