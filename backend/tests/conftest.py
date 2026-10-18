"""Tests run against REAL PostgreSQL + Redis (no mocks): DB `identityos_test`, Redis db 15.

Override with TEST_DATABASE_URL / TEST_REDIS_URL if your docker-compose credentials differ.
"""
import os
import subprocess
import sys
from contextlib import asynccontextmanager

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis
from sqlalchemy import text

from app.core.config import Settings
from app.core.security import hash_password
from app.main import create_app
from app.models.auth import User
from app.services import accounts

TEST_DB = os.environ.get("TEST_DATABASE_URL", "postgresql+asyncpg://identityos:identityos@localhost:5432/identityos_test")
TEST_REDIS = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/15")
PW = "Str0ng!Passw0rd#1"


@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings(
        _env_file=None, env="test", database_url=TEST_DB, redis_url=TEST_REDIS,
        jwt_secret_key="t" * 48, csrf_secret="c" * 48, frontend_dir="/nonexistent",
    )


@pytest.fixture(scope="session", autouse=True)
def migrated_db():
    env = {**os.environ, "DATABASE_URL": TEST_DB, "ENV": "dev", "JWT_SECRET_KEY": "x" * 40, "CSRF_SECRET": "y" * 40}
    for args in (["downgrade", "base"], ["upgrade", "head"]):
        subprocess.run([sys.executable, "-m", "alembic", *args], check=True, env=env, capture_output=True)
    subprocess.run([sys.executable, "-m", "scripts.seed", "--reset"], check=True, env=env, capture_output=True)


@pytest_asyncio.fixture
async def app(settings):
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        async with application.state.sessionmaker() as db:
            # never TRUNCATE ... CASCADE here: it would wipe the seeded demo data that references users
            await db.execute(text("DELETE FROM audit_logs WHERE NOT is_demo"))
            await db.execute(text("DELETE FROM user_roles"))
            await db.execute(text("DELETE FROM users"))
            await db.commit()
        await application.state.redis.flushdb()
        yield application


class Client:
    """httpx client with its own cookie jar that automatically echoes the CSRF token."""

    def __init__(self, app):
        self.http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    async def _csrf(self) -> dict:
        if "identityos_csrf" not in self.http.cookies:
            await self.http.get("/api/v1/auth/csrf")
        return {"X-CSRF-Token": self.http.cookies.get("identityos_csrf")}

    async def get(self, url, **kw):
        return await self.http.get(url, **kw)

    async def post(self, url, json=None, csrf=True, headers=None, **kw):
        h = {**(await self._csrf() if csrf else {}), **(headers or {})}
        return await self.http.post(url, json=json, headers=h, **kw)

    async def put(self, url, json=None, **kw):
        return await self.http.put(url, json=json, headers=await self._csrf(), **kw)

    async def login(self, email, password=PW):
        return await self.post("/api/v1/auth/login", {"email": email, "password": password})


@pytest_asyncio.fixture
async def new_client(app):
    clients = []

    def factory() -> Client:
        c = Client(app)
        clients.append(c)
        return c

    yield factory
    for c in clients:
        await c.http.aclose()


@pytest_asyncio.fixture
async def client(new_client) -> Client:
    return new_client()


@pytest_asyncio.fixture
async def make_user(app):
    async def _make(email: str, role: str = "employee", status: str = "active", password: str = PW) -> User:
        async with app.state.sessionmaker() as db:
            u = User(email=email, full_name=email.split("@")[0].title(), status=status,
                     password_hash=await hash_password(password))
            db.add(u)
            await db.flush()
            await accounts.set_roles(db, u.id, [role], None)
            await db.commit()
            return u
    return _make
