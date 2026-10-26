"""tamper-evident audit log: hash chain maintained by the database

Every inserted audit row gets a position in the chain (chain_seq), the hash of the previous row (prev_hash) and its own hash
(row_hash = sha256 of its content + prev_hash). The chain is built by a BEFORE INSERT trigger under a transaction-level advisory
lock, so it is correct under concurrent writers and no application code path can skip it. Editing, deleting or re-ordering any
past row breaks the chain at that point, which audit_chain_breaks() reports.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-26 10:00:00.000000
"""
from alembic import op

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None

LOCK_KEY = 7340211          # arbitrary constant: the advisory lock that serialises chain appends

DIGEST = """
CREATE OR REPLACE FUNCTION audit_row_digest(a audit_logs) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT encode(sha256(convert_to(concat_ws(chr(31),
      a.chain_seq::text, a.id::text,
      to_char(a.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
      coalesce(a.actor_user_id::text, ''), a.actor_label, a.action, coalesce(a.target_type, ''), coalesce(a.target_id, ''),
      coalesce(a.target_label, ''), a.category, a.severity, a.outcome, coalesce(host(a.ip_address), ''),
      coalesce(a.user_agent, ''), a.details::text, a.is_demo::text, a.prev_hash), 'UTF8')), 'hex')
$$;
"""

TRIGGER_FN = f"""
CREATE OR REPLACE FUNCTION audit_chain_append() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE last_seq bigint; last_hash text;
BEGIN
  PERFORM pg_advisory_xact_lock({LOCK_KEY});
  -- a fresh snapshot after taking the lock: sees the row appended by the transaction we waited for
  SELECT chain_seq, row_hash INTO last_seq, last_hash FROM audit_logs WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1;
  NEW.chain_seq := coalesce(last_seq, 0) + 1;
  NEW.prev_hash := coalesce(last_hash, 'GENESIS');
  NEW.row_hash := audit_row_digest(NEW);
  RETURN NEW;
END $$;
"""

BREAKS = """
CREATE OR REPLACE FUNCTION audit_chain_breaks(from_seq bigint DEFAULT 0)
RETURNS TABLE(chain_seq bigint, id bigint, problem text) LANGUAGE sql STABLE AS $$
  WITH c AS (
    SELECT a.chain_seq, a.id, a.prev_hash, a.row_hash, audit_row_digest(a) AS recomputed,
           lag(a.row_hash) OVER (ORDER BY a.chain_seq) AS prev_row_hash,
           lag(a.chain_seq) OVER (ORDER BY a.chain_seq) AS prev_seq
    FROM audit_logs a WHERE a.chain_seq IS NOT NULL AND a.chain_seq >= greatest(from_seq - 1, 0)
  )
  SELECT c.chain_seq, c.id,
         CASE WHEN c.row_hash <> c.recomputed THEN 'row content was modified'
              WHEN c.prev_seq IS NOT NULL AND c.chain_seq <> c.prev_seq + 1 THEN 'rows missing before this one (deleted)'
              ELSE 'link to the previous row does not match' END
  FROM c
  WHERE c.chain_seq >= from_seq
    AND (c.row_hash <> c.recomputed OR (c.prev_seq IS NOT NULL AND (c.prev_hash <> c.prev_row_hash OR c.chain_seq <> c.prev_seq + 1)))
  ORDER BY c.chain_seq
$$;
"""


def upgrade() -> None:
    op.execute("ALTER TABLE audit_logs ADD COLUMN chain_seq bigint, ADD COLUMN prev_hash varchar(64), ADD COLUMN row_hash varchar(64)")
    op.execute("CREATE UNIQUE INDEX ix_audit_logs_chain_seq ON audit_logs (chain_seq)")
    op.execute(DIGEST)
    # backfill existing rows in id order
    op.execute("""
    DO $$
    DECLARE r audit_logs; seq bigint := 0; prev text := 'GENESIS';
    BEGIN
      FOR r IN SELECT * FROM audit_logs ORDER BY id LOOP
        seq := seq + 1;
        r.chain_seq := seq; r.prev_hash := prev;
        r.row_hash := audit_row_digest(r);
        UPDATE audit_logs SET chain_seq = r.chain_seq, prev_hash = r.prev_hash, row_hash = r.row_hash WHERE id = r.id;
        prev := r.row_hash;
      END LOOP;
    END $$;
    """)
    op.execute(TRIGGER_FN)
    op.execute("CREATE TRIGGER audit_logs_chain BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION audit_chain_append()")
    op.execute(BREAKS)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_chain ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_chain_breaks(bigint)")
    op.execute("DROP FUNCTION IF EXISTS audit_chain_append()")
    op.execute("DROP FUNCTION IF EXISTS audit_row_digest(audit_logs)")
    op.execute("DROP INDEX IF EXISTS ix_audit_logs_chain_seq")
    op.execute("ALTER TABLE audit_logs DROP COLUMN IF EXISTS row_hash, DROP COLUMN IF EXISTS prev_hash, DROP COLUMN IF EXISTS chain_seq")
