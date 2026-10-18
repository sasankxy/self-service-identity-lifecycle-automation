import time
import uuid

import jwt
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, text

from app.models.auth import User
from app.models.governance import AuditLog
from app.services import sessions as sessions_mod
from tests.conftest import PW

SIGNUP = {"full_name": "Asha Rao", "email": "asha@corp.com", "password": PW, "confirm_password": PW}


# ------------------------------------------------------------------ signup
async def test_signup_creates_pending_user_with_argon2id_hash_and_employee_role(client, app):
    r = await client.post("/api/v1/auth/signup", SIGNUP)
    assert r.status_code == 201
    async with app.state.sessionmaker() as db:
        u = (await db.execute(select(User).where(User.email == "asha@corp.com"))).scalar_one()
        roles = (await db.execute(text("select r.name from roles r join user_roles ur on ur.role_id=r.id where ur.user_id=:i"), {"i": u.id})).scalars().all()
    assert u.status == "pending" and roles == ["employee"]
    assert u.password_hash.startswith("$argon2id$") and PW not in u.password_hash


async def test_signup_cannot_self_assign_admin(client, app):
    r = await client.post("/api/v1/auth/signup", {**SIGNUP, "role": "super_admin", "status": "active"})
    assert r.status_code == 201
    async with app.state.sessionmaker() as db:
        u = (await db.execute(select(User))).scalar_one()
        roles = (await db.execute(text("select r.name from roles r join user_roles ur on ur.role_id=r.id where ur.user_id=:i"), {"i": u.id})).scalars().all()
    assert u.status == "pending" and roles == ["employee"]


async def test_signup_duplicate_email_case_insensitive(client):
    assert (await client.post("/api/v1/auth/signup", SIGNUP)).status_code == 201
    r = await client.post("/api/v1/auth/signup", {**SIGNUP, "email": "ASHA@Corp.com"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "email_exists"


@pytest.mark.parametrize("patch,field", [
    ({"password": "short1!A", "confirm_password": "short1!A"}, "_"),
    ({"confirm_password": "Different!Passw0rd#1"}, "_"),
    ({"email": "not-an-email"}, "email"),
    ({"full_name": "A"}, "full_name"),
])
async def test_signup_validation(client, patch, field):
    r = await client.post("/api/v1/auth/signup", {**SIGNUP, **patch})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"


# ------------------------------------------------------------------ login
async def test_login_blocked_until_approved_then_works(client, new_client, make_user):
    await make_user("root@corp.com", "super_admin")
    await client.post("/api/v1/auth/signup", SIGNUP)
    r = await client.login("asha@corp.com")
    assert r.status_code == 403 and r.json()["error"]["code"] == "account_pending"

    admin = new_client()
    assert (await admin.login("root@corp.com")).status_code == 200
    pending = (await admin.get("/api/v1/admin/users?status=pending")).json()
    assert pending["total"] == 1
    uid = pending["items"][0]["id"]
    r = await admin.post(f"/api/v1/admin/users/{uid}/approve", {"role": "approver"})
    assert r.status_code == 200 and r.json()["roles"] == ["approver"]

    r = await client.login("asha@corp.com")
    assert r.status_code == 200
    me = (await client.get("/api/v1/auth/me")).json()
    assert me["roles"] == ["approver"] and "approvals:decide" in me["permissions"] and "users:approve" not in me["permissions"]


async def test_bad_password_and_unknown_user_are_indistinguishable(client, make_user):
    await make_user("a@corp.com")
    r1 = await client.login("a@corp.com", "Wrong!Passw0rd#9")
    r2 = await client.login("nobody@corp.com", "Wrong!Passw0rd#9")
    assert r1.status_code == r2.status_code == 401 and r1.json() == r2.json()


@pytest.mark.parametrize("status", ["suspended", "disabled", "rejected"])
async def test_inactive_accounts_rejected(client, make_user, status):
    await make_user("x@corp.com", status=status)
    r = await client.login("x@corp.com")
    assert r.status_code == 403 and r.json()["error"]["code"] == "account_disabled"


async def test_tokens_only_in_httponly_cookies(client, make_user):
    await make_user("a@corp.com")
    r = await client.login("a@corp.com")
    body = r.text
    assert "eyJ" not in body                       # no JWT in the response body
    cookies = {c.split("=")[0]: c.lower() for c in r.headers.get_list("set-cookie")}
    assert "httponly" in cookies["identityos_at"] and "samesite=lax" in cookies["identityos_at"]
    assert "httponly" in cookies["identityos_rt"] and "path=/api/v1/auth" in cookies["identityos_rt"]
    assert "httponly" not in cookies["identityos_csrf"]          # JS must read this one


async def test_login_rate_limited(client, make_user):
    await make_user("a@corp.com")
    codes = [(await client.login("a@corp.com", "Wrong!Passw0rd#9")).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5] == 429 and "retry-after" in (await client.login("a@corp.com")).headers
    assert (await client.login("a@corp.com")).status_code == 429     # even the right password is blocked


# ------------------------------------------------------------------ protected routes / JWT
async def test_protected_route_requires_cookie(client):
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401 and r.json()["error"]["code"] == "not_authenticated"


async def test_tampered_wrong_alg_and_wrong_type_tokens_rejected(client, make_user, settings):
    u = await make_user("a@corp.com")
    await client.login("a@corp.com")
    good = client.http.cookies.get("identityos_at")
    claims = jwt.decode(good, options={"verify_signature": False})
    forged = jwt.encode(claims, "wrong-secret-wrong-secret-wrong-secret!", algorithm="HS256")
    none_alg = jwt.encode(claims, None, algorithm="none")
    refresh_as_access = client.http.cookies.get("identityos_rt")
    for bad in (forged, none_alg, refresh_as_access, good[:-3] + "abc"):
        client.http.cookies.set("identityos_at", bad)
        r = await client.get("/api/v1/auth/me")
        assert r.status_code == 401, bad[:20]


async def test_expired_access_token_reports_token_expired(client, make_user, settings):
    u = await make_user("a@corp.com")
    await client.login("a@corp.com")
    claims = jwt.decode(client.http.cookies.get("identityos_at"), options={"verify_signature": False})
    claims["exp"] = int(time.time()) - 5
    claims["iat"] = claims["nbf"] = claims["exp"] - 60
    client.http.cookies.set("identityos_at", jwt.encode(claims, settings.jwt_secret_key, algorithm="HS256"))
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401 and r.json()["error"]["code"] == "token_expired"


# ------------------------------------------------------------------ refresh / logout / revocation
async def test_refresh_rotates_and_replay_revokes_session(client, make_user, monkeypatch):
    await make_user("a@corp.com")
    await client.login("a@corp.com")
    old_refresh = client.http.cookies.get("identityos_rt")
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 200
    new_refresh = client.http.cookies.get("identityos_rt")
    assert new_refresh and new_refresh != old_refresh
    assert (await client.get("/api/v1/auth/me")).status_code == 200

    monkeypatch.setattr(sessions_mod, "GRACE_SECONDS", -1)           # disable grace window
    attacker = client.http.cookies.jar
    client.http.cookies.set("identityos_rt", old_refresh, path="/api/v1/auth")
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 401 and r.json()["error"]["code"] == "session_revoked"
    # the legitimate (rotated) token family is dead too, and so is the access token
    client.http.cookies.set("identityos_rt", new_refresh, path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_parallel_refresh_within_grace_does_not_kill_session(client, make_user):
    await make_user("a@corp.com")
    await client.login("a@corp.com")
    old = client.http.cookies.get("identityos_rt")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 200
    client.http.cookies.set("identityos_rt", old, path="/api/v1/auth")      # second tab used the stale cookie
    assert (await client.post("/api/v1/auth/refresh")).status_code == 200
    assert (await client.get("/api/v1/auth/me")).status_code == 200


async def test_logout_revokes_session_even_for_stolen_access_token(client, make_user):
    await make_user("a@corp.com")
    await client.login("a@corp.com")
    stolen = client.http.cookies.get("identityos_at")
    assert (await client.post("/api/v1/auth/logout")).status_code == 200
    client.http.cookies.set("identityos_at", stolen)
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401 and r.json()["error"]["code"] == "session_revoked"


async def test_logout_all_revokes_other_devices(new_client, make_user):
    await make_user("a@corp.com")
    laptop, phone = new_client(), new_client()
    await laptop.login("a@corp.com"); await phone.login("a@corp.com")
    assert (await laptop.post("/api/v1/auth/logout-all")).status_code == 200
    assert (await phone.get("/api/v1/auth/me")).status_code == 401


async def test_suspension_takes_effect_immediately(new_client, make_user):
    await make_user("root@corp.com", "super_admin"); victim = await make_user("v@corp.com")
    admin, user = new_client(), new_client()
    await admin.login("root@corp.com"); await user.login("v@corp.com")
    assert (await user.get("/api/v1/auth/me")).status_code == 200
    r = await admin.post(f"/api/v1/admin/users/{victim.id}/suspend", {"reason": "test"})
    assert r.status_code == 200
    assert (await user.get("/api/v1/auth/me")).status_code == 401
    assert (await user.post("/api/v1/auth/refresh")).status_code == 401
    assert (await user.login("v@corp.com")).status_code == 403


# ------------------------------------------------------------------ CSRF
async def test_csrf_enforced_on_state_changing_requests(client, make_user):
    await make_user("a@corp.com")
    r = await client.post("/api/v1/auth/login", {"email": "a@corp.com", "password": PW}, csrf=False)
    assert r.status_code == 403 and r.json()["error"]["code"] == "csrf_failed"
    await client.http.get("/api/v1/auth/csrf")
    r = await client.post("/api/v1/auth/login", {"email": "a@corp.com", "password": PW}, csrf=False,
                          headers={"X-CSRF-Token": "forged.token"})
    assert r.status_code == 403
    r = await client.post("/api/v1/auth/login", {"email": "a@corp.com", "password": PW},
                          headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "csrf_origin"
    assert (await client.login("a@corp.com")).status_code == 200


# ------------------------------------------------------------------ RBAC
async def test_backend_enforces_roles(new_client, make_user):
    await make_user("emp@corp.com", "employee"); await make_user("apr@corp.com", "approver")
    await make_user("aud@corp.com", "auditor")
    for email in ("emp@corp.com", "apr@corp.com", "aud@corp.com"):
        c = new_client(); await c.login(email)
        r = await c.get("/api/v1/admin/users")
        assert r.status_code == 403, email
        assert r.json()["error"]["code"] == "forbidden"
    anon = new_client()
    assert (await anon.get("/api/v1/admin/users")).status_code == 401


async def test_iam_admin_cannot_grant_or_touch_privileged_roles(new_client, make_user):
    await make_user("iam@corp.com", "iam_admin"); boss = await make_user("boss@corp.com", "super_admin")
    pend = await make_user("p@corp.com", status="pending")
    c = new_client(); await c.login("iam@corp.com")
    assert (await c.post(f"/api/v1/admin/users/{pend.id}/approve", {"role": "super_admin"})).status_code == 403
    assert (await c.post(f"/api/v1/admin/users/{pend.id}/approve", {"role": "iam_admin"})).status_code == 403
    assert (await c.post(f"/api/v1/admin/users/{boss.id}/suspend", {})).status_code == 403
    assert (await c.put(f"/api/v1/admin/users/{boss.id}/roles", {"roles": ["employee"]})).status_code == 403
    assert (await c.post(f"/api/v1/admin/users/{pend.id}/approve", {"role": "auditor"})).status_code == 200


async def test_admin_cannot_approve_or_suspend_self(new_client, make_user):
    me = await make_user("root@corp.com", "super_admin")
    c = new_client(); await c.login("root@corp.com")
    assert (await c.post(f"/api/v1/admin/users/{me.id}/suspend", {})).status_code == 403
    assert (await c.put(f"/api/v1/admin/users/{me.id}/roles", {"roles": ["employee"]})).status_code == 403


# ------------------------------------------------------------------ Redis cache / failure mode
async def test_principal_cache_has_no_secrets_and_is_invalidated(client, make_user, app):
    u = await make_user("a@corp.com")
    await client.login("a@corp.com"); await client.get("/api/v1/auth/me")
    raw = await app.state.redis.get(f"principal:{u.id}")
    assert raw and "argon2" not in raw and "password" not in raw.lower() and "eyJ" not in raw
    assert 0 < await app.state.redis.ttl(f"principal:{u.id}") <= 60


async def test_fails_closed_when_redis_is_down(client, make_user, app):
    await make_user("a@corp.com")
    await client.login("a@corp.com")
    real = app.state.redis
    app.state.redis = Redis.from_url("redis://localhost:1/0", decode_responses=True, socket_connect_timeout=0.2)
    try:
        r = await client.get("/api/v1/auth/me")
        assert r.status_code == 503 and r.json()["error"]["code"] == "session_store_unavailable"
        assert (await client.login("a@corp.com")).status_code == 503
        assert (await client.post("/api/v1/auth/signup", {**SIGNUP, "email": "z@corp.com"})).status_code == 503
    finally:
        await app.state.redis.aclose()
        app.state.redis = real


# ------------------------------------------------------------------ audit
async def test_security_events_audited_without_secrets(client, make_user, app):
    await make_user("a@corp.com")
    await client.login("a@corp.com", "Wrong!Passw0rd#9")
    await client.login("a@corp.com")
    await client.post("/api/v1/auth/logout")
    async with app.state.sessionmaker() as db:
        rows = (await db.execute(select(AuditLog).where(AuditLog.is_demo.is_(False)).order_by(AuditLog.id))).scalars().all()
    assert [(r.action, r.outcome) for r in rows] == [("auth.login", "failure"), ("auth.login", "success"), ("auth.logout", "success")]
    blob = " ".join(str(r.details) + (r.user_agent or "") for r in rows)
    assert "Passw0rd" not in blob and "eyJ" not in blob


async def test_signup_domain_allowlist(app, client, settings):
    app.state.settings = settings.model_copy(update={"allowed_email_domains": "corp.com"})
    r = await client.post("/api/v1/auth/signup", {**SIGNUP, "email": "x@gmail.com"})
    assert r.status_code == 422 and "email" in r.json()["error"]["fields"]
    assert (await client.post("/api/v1/auth/signup", SIGNUP)).status_code == 201
