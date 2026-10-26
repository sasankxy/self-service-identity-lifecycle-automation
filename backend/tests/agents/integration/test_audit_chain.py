"""Tamper-evident audit log (alembic 0004): every write path is chained, and edits/deletions are detected."""
import asyncio

from sqlalchemy import text

from app.api.v1 import audit_integrity
from app.services import audit


async def head_seq(app) -> int:
    async with app.state.sessionmaker() as db:
        return (await db.execute(text("SELECT coalesce(max(chain_seq), 0) FROM audit_logs"))).scalar_one()


async def write_events(app, n: int, tag: str):
    async with app.state.sessionmaker() as db:
        for i in range(n):
            audit.record(db, None, f"test.{tag}", actor_label="chain-test", details={"i": i})
        await db.commit()


async def test_new_rows_are_chained_and_verify(app):
    start = await head_seq(app) + 1
    await write_events(app, 5, "chain")
    async with app.state.sessionmaker() as db:
        rows = (await db.execute(text("SELECT chain_seq, prev_hash, row_hash FROM audit_logs WHERE chain_seq >= :s ORDER BY chain_seq"),
                                 {"s": start})).all()
        assert len(rows) == 5 and all(len(r.row_hash) == 64 for r in rows)
        assert all(rows[k].prev_hash == rows[k - 1].row_hash for k in range(1, 5))
        out = await audit_integrity.verify(db, start)
    assert out["ok"] and out["checked"] == 5 and out["head"]["chain_seq"] == start + 4


async def test_concurrent_writers_keep_one_linear_chain(app):
    start = await head_seq(app) + 1
    await asyncio.gather(*(write_events(app, 3, f"conc{k}") for k in range(6)))
    async with app.state.sessionmaker() as db:
        seqs = (await db.execute(text("SELECT chain_seq FROM audit_logs WHERE chain_seq >= :s ORDER BY chain_seq"), {"s": start})).scalars().all()
        assert seqs == list(range(start, start + 18))                       # no gaps, no forks
        assert (await audit_integrity.verify(db, start))["ok"]


async def test_edit_and_delete_are_detected(app):
    start = await head_seq(app) + 1
    await write_events(app, 4, "tamper")
    async with app.state.sessionmaker() as db:
        await db.execute(text("UPDATE audit_logs SET actor_label = 'forged' WHERE chain_seq = :s"), {"s": start + 1})
        await db.execute(text("DELETE FROM audit_logs WHERE chain_seq = :s"), {"s": start + 2})
        out = await audit_integrity.verify(db, start)
        await db.rollback()                                                  # leave the real log untouched
    problems = {b["chain_seq"]: b["problem"] for b in out["breaks"]}
    assert not out["ok"]
    assert problems[start + 1] == "row content was modified"
    assert problems[start + 3] == "rows missing before this one (deleted)"


async def test_integrity_endpoint_permissions(new_client, make_user):
    await make_user("aud-chain@corp.com", "auditor")
    await make_user("emp-chain@corp.com", "employee")
    aud, emp = new_client(), new_client()
    await aud.login("aud-chain@corp.com")
    await emp.login("emp-chain@corp.com")
    r = await aud.get("/api/v1/audit-logs/integrity")
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["head"]["row_hash"]
    assert (await emp.get("/api/v1/audit-logs/integrity")).status_code == 403
