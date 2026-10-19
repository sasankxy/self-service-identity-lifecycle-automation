"""governance findings and scan runs

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-19 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('governance_findings',
    sa.Column('kind', sa.String(length=10), nullable=False),
    sa.Column('rule', sa.String(length=40), nullable=False),
    sa.Column('identity_id', sa.UUID(), nullable=False),
    sa.Column('subject_key', sa.String(length=80), server_default='', nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('status', sa.String(length=10), server_default='open', nullable=False),
    sa.Column('title', sa.String(length=240), nullable=False),
    sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
    sa.Column('source', sa.String(length=20), server_default='scan', nullable=False),
    sa.Column('first_detected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_detected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('dismissed_by', sa.UUID(), nullable=True),
    sa.Column('dismissed_reason', sa.String(length=300), nullable=True),
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.CheckConstraint("kind IN ('orphan','creep')", name=op.f('ck_governance_findings_kind_valid')),
    sa.CheckConstraint("severity IN ('low','medium','high','critical')", name=op.f('ck_governance_findings_severity_valid')),
    sa.CheckConstraint("status IN ('open','resolved','dismissed')", name=op.f('ck_governance_findings_status_valid')),
    sa.ForeignKeyConstraint(['dismissed_by'], ['users.id'], name=op.f('fk_governance_findings_dismissed_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['identity_id'], ['identities.id'], name=op.f('fk_governance_findings_identity_id_identities'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_governance_findings')),
    sa.UniqueConstraint('rule', 'identity_id', 'subject_key', name='uq_governance_findings_key')
    )
    op.create_index('ix_governance_findings_status_kind', 'governance_findings', ['status', 'kind'], unique=False)
    op.create_index('ix_governance_findings_identity', 'governance_findings', ['identity_id'], unique=False)
    op.create_table('governance_scan_runs',
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('trigger', sa.String(length=12), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('identities_scanned', sa.Integer(), server_default='0', nullable=False),
    sa.Column('opened', sa.Integer(), server_default='0', nullable=False),
    sa.Column('resolved', sa.Integer(), server_default='0', nullable=False),
    sa.Column('open_total', sa.Integer(), server_default='0', nullable=False),
    sa.Column('applied_due', sa.Integer(), server_default='0', nullable=False),
    sa.Column('error', sa.String(length=500), nullable=True),
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.CheckConstraint("status IN ('ok','failed')", name=op.f('ck_governance_scan_runs_status_valid')),
    sa.CheckConstraint("trigger IN ('scheduled','manual','cli')", name=op.f('ck_governance_scan_runs_trigger_valid')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_governance_scan_runs'))
    )
    op.create_index('ix_governance_scan_runs_started_at', 'governance_scan_runs', ['started_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_governance_scan_runs_started_at', table_name='governance_scan_runs')
    op.drop_table('governance_scan_runs')
    op.drop_index('ix_governance_findings_identity', table_name='governance_findings')
    op.drop_index('ix_governance_findings_status_kind', table_name='governance_findings')
    op.drop_table('governance_findings')
