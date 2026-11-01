"""Aadhaar verification of joiners: stores outcomes only, never the card image or the full number

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-01 10:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('identity_verifications',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('identity_id', sa.UUID(), nullable=False),
    sa.Column('status', sa.String(length=10), server_default='pending', nullable=False),
    sa.Column('expected_dob', sa.Date(), nullable=True),
    sa.Column('expected_gender', sa.String(length=1), nullable=True),
    sa.Column('token_hash', sa.String(length=64), nullable=True),
    sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('attempts', sa.Integer(), server_default='0', nullable=False),
    sa.Column('masked_number', sa.String(length=20), nullable=True),
    sa.Column('number_hash', sa.String(length=64), nullable=True),
    sa.Column('checks', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
    sa.Column('consent_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('pending','verified','review','failed')", name='ck_identity_verifications_status_valid'),
    sa.ForeignKeyConstraint(['identity_id'], ['identities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('identity_id', name='uq_identity_verifications_identity'),
    sa.UniqueConstraint('token_hash', name='uq_identity_verifications_token'))
    op.create_index('ix_identity_verifications_number_hash', 'identity_verifications', ['number_hash'])


def downgrade() -> None:
    op.drop_index('ix_identity_verifications_number_hash', table_name='identity_verifications')
    op.drop_table('identity_verifications')
