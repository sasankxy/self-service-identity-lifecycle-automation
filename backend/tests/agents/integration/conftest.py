import pytest
from sqlalchemy import text

# Other tests assert on named seed people (Kai Chen) and pick low-risk people from these departments; agent tests that create
# requests must stay out of them. Moves go to Legal, which no other test reads.
BUSY_DEPTS = ("Engineering", "Finance", "Marketing", "Sales", "Support", "Legal")
QUIET_TARGET = "Legal"


async def bystander(app, offset: int, column: str = "id"):
    """The offset-th low-risk active identity outside BUSY_DEPTS with a unique, NLU-friendly name and no open request.
    Offsets: gateway DB tests use 0-1, chat tests use 2+, so no two tests share a person."""
    async with app.state.sessionmaker() as db:
        return (await db.execute(text(
            f"SELECT i.{column} FROM identities i JOIN departments d ON d.id = i.department_id WHERE i.lifecycle_state = 'active' "
            "AND i.risk_score < 40 AND d.name NOT IN (SELECT unnest(CAST(:busy AS text[]))) "
            "AND i.full_name ~ '^[A-Z][a-z]+ [A-Z][a-z]+$' AND (SELECT count(*) FROM identities x WHERE x.full_name = i.full_name) = 1 "
            "AND NOT EXISTS (SELECT 1 FROM lifecycle_requests r WHERE r.identity_id = i.id AND r.status = 'pending_approval') "
            "ORDER BY i.employee_id OFFSET :o LIMIT 1"), {"o": offset, "busy": list(BUSY_DEPTS)})).scalar_one()


@pytest.fixture
async def as_role(new_client, make_user):
    async def _as(role: str, email: str | None = None):
        email = email or f"agent-{role}@corp.com"
        await make_user(email, role)
        c = new_client()
        assert (await c.login(email)).status_code == 200
        return c
    return _as


async def unheld_app(app, email: str) -> str:
    """A low/medium-risk application with exactly one entitlement that the identity does not hold (so a request is unambiguous)."""
    async with app.state.sessionmaker() as db:
        return (await db.execute(text(
            "SELECT e.application FROM entitlements e GROUP BY e.application HAVING count(*) = 1 "
            "AND bool_and(e.risk_level IN ('low','medium')) AND bool_and(NOT e.requires_approval) "
            "AND NOT EXISTS (SELECT 1 FROM identity_entitlements ie JOIN identities i ON i.id = ie.identity_id JOIN entitlements x "
            "ON x.id = ie.entitlement_id WHERE lower(i.email) = lower(:m) AND x.application = e.application AND ie.status IN ('active','pending')) "
            "ORDER BY e.application LIMIT 1"), {"m": email})).scalar_one()
