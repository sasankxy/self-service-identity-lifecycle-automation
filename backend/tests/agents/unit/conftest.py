"""Agent unit tests: pure logic, no PostgreSQL / Redis. Database-backed agent tests live in tests/agents/integration."""
import time
import uuid
from types import SimpleNamespace

import pytest

from app.agents import capabilities
from app.services.accounts import Principal


@pytest.fixture(scope="session", autouse=True)
def migrated_db():
    """Overrides the suite-wide migration fixture in tests/conftest.py: these tests never touch the database."""
    yield


def principal(role: str = "iam_admin", email: str = "admin@corp.test") -> Principal:
    from app.core.rbac import ROLES
    return Principal(id=str(uuid.uuid4()), email=email, full_name="Test Actor", status="active", roles=[role],
                     permissions=list(ROLES[role]["permissions"]))


@pytest.fixture
def admin() -> Principal:
    return principal("iam_admin")


@pytest.fixture
def employee() -> Principal:
    return principal("employee", "emp@corp.test")


class FakeResult:
    def __init__(self, rows=()):
        self._rows = list(rows)

    def scalars(self):
        return iter(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class FakeDB:
    """Just enough AsyncSession for the gateway: get() from a dict, add() collects, execute() returns nothing."""
    def __init__(self, objects: dict | None = None):
        self.objects = objects or {}
        self.added, self.commits, self.rollbacks = [], 0, 0

    async def get(self, model, key):
        return self.objects.get(key)

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, *_a, **_k):
        return FakeResult()

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1

    def audit_actions(self) -> list[str]:
        return [getattr(o, "action", None) for o in self.added]


class FakeRedis:
    def __init__(self):
        self.kv = {}

    async def set(self, k, v, nx=False, ex=None):
        if nx and k in self.kv:
            return None
        self.kv[k] = v
        return True

    async def delete(self, k):
        self.kv.pop(k, None)


def fake_identity(email: str = "kai.chen@corp.test", name: str = "Kai Chen"):
    return SimpleNamespace(id=uuid.uuid4(), email=email, full_name=name, lifecycle_state="active")


def fake_line(name: str, risk: str = "low", action: str = "add", decision: str = "auto"):
    return SimpleNamespace(entitlement_id=uuid.uuid4(), name=name, application="App", risk_level=risk, action=action, decision=decision,
                           reason="test")


def fake_plan(kind: str = "access_request", decision: str = "auto", identity=None, lines=()):
    lines = list(lines)
    return SimpleNamespace(kind=kind, decision=decision, identity=identity or fake_identity(), lines=lines,
                           adds=[l for l in lines if l.action == "add"], removes=[l for l in lines if l.action == "remove"],
                           reasons=["Everything requested is within policy."], to_dept=None)


@pytest.fixture
def cap_for():
    def make(p: Principal, **kw):
        return capabilities.mint(p, **kw)
    return make


@pytest.fixture
def expired_cap(admin):
    c = capabilities.mint(admin)
    return capabilities.Capability(c.actor_id, c.actor_email, c.permissions, c.tools, c.targets, time.time() - 1)
