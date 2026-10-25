# IdentityOS — Phase 1: Auth, Database, Seed Data and a fully database-driven UI

## Layout
```
identityos/
├── .env.example               # copy to .env (never commit)
├── backend/
│   ├── app/
│   │   ├── main.py            # app factory, lifespan (engine/redis), headers, static frontend
│   │   ├── core/              # config, security (Argon2id/JWT), rbac, csrf, cookies, deps, errors
│   │   ├── models/            # 22 SQLAlchemy 2.x tables (auth, directory, workflow, governance, compliance)
│   │   ├── schemas/           # Pydantic request/response models
│   │   ├── services/          # sessions, ratelimit, accounts, audit, cache (cache-aside), stats (all aggregates)
│   │   └── api/v1/            # auth, admin, dashboard, identities, approvals, risk, governance, audit_logs, assistant, meta
│   ├── alembic/               # 0001_initial_schema, 0002_workflow_detail_compliance_certification
│   ├── scripts/               # create_admin.py, seed.py
│   └── tests/                 # 55 tests (auth + data API), real Postgres + Redis
└── frontend/                  # your original look & feel; pages.js now renders every page from the API
```
FastAPI serves `frontend/` same-origin, so cookies are first-party, CORS stays closed, and SameSite works.

## Run it
```bash
cp .env.example .env     # set JWT_SECRET_KEY and CSRF_SECRET:
                         #   python -c "import secrets; print(secrets.token_urlsafe(64))"
                         # DATABASE_URL / REDIS_URL must match your docker compose
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
alembic upgrade head
python -m scripts.create_admin --email you@corp.com --name "Your Name"   # first Super Admin
python -m scripts.seed                                                    # demo data (idempotent; --reset to rebuild)
uvicorn app.main:app --reload --port 8000
```
Open http://localhost:8000 (API docs: /api/docs in dev). Public signup can never create admins, hence the CLI.

Tests (create DB `identityos_test` once; Redis db 15 is flushed by tests):
```bash
createdb identityos_test      # or: docker compose exec postgres createdb -U <user> identityos_test
TEST_DATABASE_URL=postgresql+asyncpg://<user>:<pw>@localhost:5432/identityos_test pytest
```

## API
All routes are under `/api/v1`, need the login cookies, and are permission-checked on the server. State-changing calls need `X-CSRF-Token`.

| Area | Endpoints | Permission |
|---|---|---|
| Auth | `GET /auth/csrf`, `POST /auth/signup · login · refresh · logout · logout-all`, `GET /auth/me` | public / session |
| Portal accounts | `GET /admin/users`, `POST /admin/users/{id}/approve · reject · suspend · reactivate`, `PUT /admin/users/{id}/roles` | `users:*` |
| Dashboard | `GET /dashboard/summary · trends · activity` | `dashboard:read` |
| Identities | `GET /identities?state=&q=&limit=&offset=`, `GET /identities/counts`, `GET /identities/{id}`, `POST /identities` | `identities:read` / `identities:write` |
| Approvals | `GET /approvals?status=pending\|approved\|rejected\|all`, `POST /approvals/{id}/approve · reject` | `approvals:read` / `approvals:decide` |
| Risk | `GET /risk/summary · flagged`, `GET /risk/flagged/export` (CSV) | `risk:read` |
| Governance | `GET /governance/summary`, `POST /governance/campaigns` | `governance:read` / `governance:manage` |
| Audit | `GET /audit-logs?category=&severity=&q=`, `GET /audit-logs/export` (CSV) | `audit:read` |
| Assistant | `POST /assistant/query` (NLU-parsed, read-only lookups) | `identities:read` |
| Misc | `GET /meta/lookups`, `GET /health` | `identities:read` / public |

Errors are always `{"error": {"code", "message", "fields?"}}`. Interactive docs: `/api/docs` (dev only).

## Where every number on screen comes from
Nothing operational is stored as a total; every figure is computed from rows at request time (cached in Redis for 15-60 s and invalidated on every write).
| UI | Source |
|---|---|
| Total identities, growth | `identities` (non-terminated), vs rows created > 7 days ago |
| Provisioning success | completed / (completed + failed) `lifecycle_requests`, last 30 days; SLA target from the `sla` governance policy |
| Pending approvals / urgent / avg wait | `approval_requests` where `status='pending'` |
| High-risk accounts, risk tiers | `identities.risk_score` (= latest `risk_assessments` row) |
| Lifecycle trends, request distribution | `lifecycle_requests` grouped by month / type, last 6 months |
| Risk trajectory | average `risk_assessments.score` per 5-day bucket |
| Risk triggers chart | first trigger of each flagged identity's latest assessment |
| Compliance %, frameworks | passing / tested `compliance_controls` |
| Certification progress | decided / total `certification_items` |
| SoD conflicts | identities holding *all* entitlements of an active `sod` policy |
| Activity feed, audit log | `audit_logs` |
| Connector status | `identity_connectors` (seeded only as Demo / Not Configured / Disconnected) |

## Seed data
`python -m scripts.seed` creates ~420 identities, ~330 lifecycle requests with approvals, ~2,700 risk assessments, ~170 audit events, 4 compliance frameworks (74 controls), 3 certification campaigns and 7 simulated connectors. IDs are `uuid5`, so re-running changes nothing; `--reset` deletes only `is_demo` rows and rebuilds. Every seeded row has `is_demo = true`, employee ids start with `DEMO-`, and no connector is ever `connected`. Dates are relative to the moment you seed, so the data always looks current.

## Approval semantics (important)
Approving or rejecting is one database transaction (decision + side effects + audit row, with a row lock so two people cannot both decide). Because no live connector exists yet, approval **records** the decision and sets grants to `pending` (joiner/mover/privilege) or `revoked` (leaver/removed); it does not provision anything, and the UI says so.

## Design decisions
* **Platform users vs identities**: `users` (portal logins) and `identities` (managed employees) are separate tables with no link.
* **Sessions**: `session:{sid}` in Redis is the single source of truth. Access JWT (15 min) and refresh JWT (7 d sliding, 30 d absolute) both carry `sid`; deleting the key kills both instantly (logout, suspension, reuse detection). Refresh rotation is an atomic Lua script; replaying an old refresh token revokes the session (10 s grace for parallel tabs).
* **Redis down → fail closed**: login, refresh, signup and every authenticated request return 503 rather than skipping checks.
* **Cache-aside**: `principal:{uid}` (status, roles, permissions, 60 s TTL, no secrets) is invalidated on every approve/reject/suspend/role change.
* **Login flow note**: Postgres is always read at login because it holds the hash. The Redis account-metadata cache is used on every subsequent request (where it saves a DB hit); it is intentionally not used to short-circuit login, which would leak account state before the password is verified.
* **CSRF**: signed double-submit token in `X-CSRF-Token` + Origin check on every non-GET, including login. Refresh cookie is path-scoped to `/api/v1/auth`.
* **Enumeration**: bad password and unknown email return the same 401; account status is only revealed after a correct password. Signup does reveal "email already exists" (stated trade-off; it is rate limited).
* **Privilege rules**: only Super Admin can grant/remove `iam_admin`/`super_admin` or act on privileged accounts; nobody can approve/suspend/re-role themselves.
* **JWT keys**: `JWT_ALGORITHM` = HS256/384/512 with `JWT_SECRET_KEY`, or RS*/ES*/EdDSA with PEM paths. Algorithm is pinned on decode; `none` is rejected.

## Known gaps
* The directory assistant is rule-based (name lookups, risk, pending approvals); it is not an LLM and cannot change access.
* No live connectors: provisioning/deprovisioning is recorded, not executed.
* Removed because they were simulated: the Edit buttons, "Remediate" (now "Review", opens the identity), and the canned AI replies.
* A CSP header is deferred because the existing HTML uses inline `onclick` handlers.
* Thresholds (75 / 40 risk bands) are constants in `services/stats.py`, mirrored in two UI labels.

## AI Assistant: NLU -> policy engine -> confirm -> execute
```
text -> custom NLU (backend/nlu: rules + CRF + NB, vocabulary loaded from the directory DB)
     -> entity resolution against PostgreSQL (people, departments, applications, entitlements)
     -> policy engine (app/services/policy.py, deterministic)   AUTO | APPROVAL | DENY | CLARIFY
     -> user clicks Confirm  ->  POST /assistant/execute (server re-plans; client decision is only compared)
```
* **Compound requests**: "Move X from Engineering to Finance and give him access to SAP starting next Monday" is ONE mover request with a resource.
* **Policy** (see the docstring in `policy.py`): baseline-of-target-department / low-medium-risk access is auto-approved; high/critical,
  `requires_approval`, outside-baseline access, or a high-risk person (score >= 75) goes to the approvals queue; SoD conflicts and
  leaver/terminated identities are denied; revocations are always auto. Free-text justification never influences the decision.
* **Execution**: AUTO requests are stored as approved (approver = policy, audited) and applied through the same code as the approvals API
  (`services/lifecycle.apply_effects`). Future-dated ones are *scheduled*: run `python -m scripts.apply_due` from cron.
  No live connector exists, so entitlements become `pending` provisioning exactly as for human approvals.
* **SLM (optional, local)**: `ollama pull qwen2.5:3b`, set `SLM_ENABLED=true` (+ `OLLAMA_MODEL`). Consulted only when the custom engine cannot
  interpret a request or a joiner/mover names no known department. Output is JSON-schema constrained, validated against the catalogue, and
  surfaced only as a clickable *suggested rephrasing*; it cannot grant, approve or execute. Disabled/unreachable => assistant just says it did not understand.
* **Experiment**: `python -m nlu.evaluation.compare_slm --model qwen2.5:3b --show-failures` (custom engine vs SLM: intent accuracy, entity P/R/F1,
  latency, hallucination rate).
* Vocabulary bridge to edit: `DEPT_ALIASES` / `APP_ALIASES` in `app/services/nlu.py`.

## Agent layer: multi-agent pipeline (`backend/app/agents`, `AGENT_MODE=graph`)
```
POST /api/v1/agent/chat -> LangGraph conversation graph (state checkpointed in Postgres per user + chat session)
  sentinel   sanitise + injection/jailbreak detection (blocked turns are audited as agent.guard_block)
  understand NLU + conversation memory -> typed intent/slots (Integration Contract v1, docs/contract/)
  lifecycle  resolve person -> ONE whitelisted tool call -> Action Gateway preview (policy engine re-run)
  confirm    pauses (interrupt) until POST /api/v1/agent/resume {session_id, call_id, confirm}
             -> Action Gateway commit (policy re-checked) -> lifecycle/onboarding services -> agent.tool_executed audit
```
* **Action Gateway** (`agents/gateway.py`) is the only thing that executes a tool: whitelist, strict schema, per-turn capability token,
  portal permission, catalogue, policy re-evaluation, verifier (self-grant / high-risk grants can only get stricter), idempotency, audit.
* `AGENT_MODE=legacy` (default) keeps the chat UI on `/assistant/*`; `graph` switches it to `/agent/*`. `AGENT_CHECKPOINTER=memory`
  keeps conversations in process memory instead of Postgres (tests always use memory).
* Tests: `pytest tests/agents/unit` (no services), `pytest tests/agents/integration` (Postgres + Redis). CI runs both on every push.
* **LLM agents** (any OpenAI-compatible API, Groq by default): set `AGENT_LLM_ENABLED=true` and `AGENT_LLM_API_KEY` in `backend/.env`.
  The agents are: Sentinel (prompt-guard classifier), Extractor and Planner (`gpt-oss-120b`, used when the NLU is unsure or the
  request is compound), Narrator (`gpt-oss-20b`, grounded summaries), Investigator ("why does X have Y?") and Approver Copilot
  ("should I approve REQ-123?"), both advisory. Models can only understand, decompose, judge or word things; tool calls are still
  built from quarantined slots and executed only by the Action Gateway. There's a per-turn call budget and a circuit breaker, and
  without a key the system runs fully deterministically.
* **Employee self-service:** a portal user with the default `employee` role (permission `self:read` + `self:request`) sees only the
  AI Assistant, which covers *their own* access: "what access do I have?", "why do I have X?", "I need access to GitHub",
  "remove my Zoom access". The login is linked to the directory identity with the same e-mail, and anything they ask for
  themselves goes to an approver.
