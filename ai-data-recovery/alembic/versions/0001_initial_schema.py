"""initial_schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-09-26 06:25:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.UniqueConstraint('email', name='uq_users_email')
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # 2. recovery_jobs table
    op.create_table(
        'recovery_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('job_name', sa.String(length=255), nullable=False, server_default='Forensic Recovery Job'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='pending'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('operation', sa.String(length=64), nullable=False, server_default='recover_corrupted'),
        sa.Column('source_type', sa.String(length=64), nullable=False, server_default='uploaded_file'),
        sa.Column('source_path', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('target_filename', sa.String(length=256), nullable=True),
        sa.Column('target_type', sa.String(length=32), nullable=True),
        sa.Column('current_stage', sa.String(length=64), server_default='created', nullable=True),
        sa.Column('progress', sa.Integer(), server_default='0', nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'analyzing', 'scanning', 'fragmenting', 'reconstructing', 'validating', 'completed', 'partial', 'failed')",
            name='ck_recovery_jobs_status'
        )
    )
    op.create_index('ix_recovery_jobs_user_id', 'recovery_jobs', ['user_id'])
    op.create_index('ix_recovery_jobs_status', 'recovery_jobs', ['status'])
    op.create_index('ix_recovery_jobs_created_at', 'recovery_jobs', ['created_at'])

    # 3. files table
    op.create_table(
        'files',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('recovery_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('original_name', sa.String(length=255), nullable=False),
        sa.Column('detected_type', sa.String(length=64), nullable=False),
        sa.Column('mime_type', sa.String(length=128), nullable=True),
        sa.Column('file_size', sa.BigInteger(), nullable=False),
        sa.Column('file_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(length=1024), nullable=False),
        sa.Column('damage_percentage', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('status', sa.String(length=32), server_default='uploaded', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.CheckConstraint('damage_percentage >= 0.0 AND damage_percentage <= 100.0', name='ck_files_damage_percentage')
    )
    op.create_index('ix_files_job_id', 'files', ['job_id'])
    op.create_index('ix_files_file_hash', 'files', ['file_hash'])

    # 4. fragments table
    op.create_table(
        'fragments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('file_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('files.id', ondelete='CASCADE'), nullable=False),
        sa.Column('fragment_index', sa.Integer(), nullable=False),
        sa.Column('offset_start', sa.BigInteger(), nullable=False),
        sa.Column('offset_end', sa.BigInteger(), nullable=False),
        sa.Column('fragment_size', sa.Integer(), nullable=False),
        sa.Column('fragment_hash', sa.String(length=64), nullable=False),
        sa.Column('confidence', sa.Float(), server_default='100.0', nullable=False),
        sa.Column('is_valid', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('storage_path', sa.String(length=1024), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('entropy', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('predicted_type', sa.String(length=32), server_default='unknown', nullable=True),
        sa.Column('is_header', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('is_footer', sa.Boolean(), server_default='false', nullable=True),
        sa.CheckConstraint('confidence >= 0.0 AND confidence <= 100.0', name='ck_fragments_confidence')
    )
    op.create_index('ix_fragments_file_id', 'fragments', ['file_id'])

    # 5. ai_analysis table
    op.create_table(
        'ai_analysis',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('file_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('files.id', ondelete='CASCADE'), nullable=False),
        sa.Column('detected_file_type', sa.String(length=64), nullable=False),
        sa.Column('corruption_type', sa.String(length=128), nullable=False),
        sa.Column('damaged_regions', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('predicted_structure', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('confidence', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('explanation', sa.Text(), nullable=True),
        sa.Column('model_name', sa.String(length=128), server_default='forensic-ai-v1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.UniqueConstraint('file_id', name='uq_ai_analysis_file_id'),
        sa.CheckConstraint('confidence >= 0.0 AND confidence <= 100.0', name='ck_ai_analysis_confidence')
    )
    op.create_index('ix_ai_analysis_file_id', 'ai_analysis', ['file_id'])

    # 6. recovery_results table
    op.create_table(
        'recovery_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('file_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('files.id', ondelete='CASCADE'), nullable=False),
        sa.Column('recovered_path', sa.String(length=1024), nullable=False),
        sa.Column('recovered_size', sa.BigInteger(), server_default='0', nullable=False),
        sa.Column('recovery_percentage', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('validation_status', sa.String(length=64), server_default='pending', nullable=False),
        sa.Column('validation_details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('output_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.CheckConstraint('recovery_percentage >= 0.0 AND recovery_percentage <= 100.0', name='ck_recovery_results_recovery_percentage')
    )
    op.create_index('ix_recovery_results_file_id', 'recovery_results', ['file_id'])

    # 7. audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('recovery_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False)
    )
    op.create_index('ix_audit_logs_job_id', 'audit_logs', ['job_id'])

    # Legacy/auxiliary tables for forensic scan workers
    op.create_table(
        'sources',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('recovery_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source_path', sa.String(length=512), nullable=False),
        sa.Column('source_sha256', sa.String(length=64), nullable=False),
        sa.Column('source_size', sa.Integer(), nullable=False),
        sa.Column('source_type', sa.String(length=64), nullable=False),
        sa.Column('sector_size', sa.Integer(), server_default='512', nullable=True),
        sa.Column('filesystem_detected', sa.String(length=32), server_default='unknown', nullable=True),
        sa.Column('acquired_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('is_read_only', sa.Boolean(), server_default='true', nullable=True)
    )
    op.create_index('ix_sources_job_id', 'sources', ['job_id'])

    op.create_table(
        'legacy_fragments',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('recovery_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source_offset', sa.Integer(), nullable=False),
        sa.Column('length', sa.Integer(), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('predicted_type', sa.String(length=32), server_default='unknown', nullable=True),
        sa.Column('type_probabilities', sa.Text(), nullable=True),
        sa.Column('entropy', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('status', sa.String(length=32), server_default='valid', nullable=True),
        sa.Column('source_region', sa.String(length=64), server_default='unallocated', nullable=True),
        sa.Column('is_header', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('is_footer', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('creation_time', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True)
    )
    op.create_index('ix_legacy_fragments_job_id', 'legacy_fragments', ['job_id'])

    op.create_table(
        'fragment_relationships',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('recovery_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('from_fragment_id', sa.String(length=64), nullable=False),
        sa.Column('to_fragment_id', sa.String(length=64), nullable=False),
        sa.Column('probability', sa.Float(), nullable=False),
        sa.Column('model_version', sa.String(length=64), server_default='v1.0', nullable=True),
        sa.Column('relationship_type', sa.String(length=32), server_default='likely_successor', nullable=True),
        sa.Column('feature_metadata', sa.Text(), nullable=True)
    )
    op.create_index('ix_fragment_relationships_job_id', 'fragment_relationships', ['job_id'])

    op.create_table(
        'reconstruction_candidates',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('recovery_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('rank', sa.Integer(), server_default='1', nullable=True),
        sa.Column('fragment_sequence', sa.Text(), nullable=False),
        sa.Column('score', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('parser_valid', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('is_selected', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('evidence_details', sa.Text(), nullable=True)
    )
    op.create_index('ix_reconstruction_candidates_job_id', 'reconstruction_candidates', ['job_id'])

    op.create_table(
        'recovered_files',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('recovery_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('filename', sa.String(length=256), nullable=False),
        sa.Column('file_type', sa.String(length=32), nullable=False),
        sa.Column('output_path', sa.String(length=512), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('recovered_bytes', sa.Integer(), server_default='0', nullable=True),
        sa.Column('missing_bytes', sa.Integer(), server_default='0', nullable=True),
        sa.Column('fabricated_bytes', sa.Integer(), server_default='0', nullable=True),
        sa.Column('recoverability_score', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('integrity_score', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('model_confidence', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('status', sa.String(length=32), server_default='recovered', nullable=True),
        sa.Column('validation_details', sa.Text(), nullable=True),
        sa.Column('fragments_used', sa.Text(), nullable=True),
        sa.Column('missing_regions', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True)
    )
    op.create_index('ix_recovered_files_job_id', 'recovered_files', ['job_id'])


def downgrade() -> None:
    op.drop_table('recovered_files')
    op.drop_table('reconstruction_candidates')
    op.drop_table('fragment_relationships')
    op.drop_table('legacy_fragments')
    op.drop_table('sources')
    op.drop_table('audit_logs')
    op.drop_table('recovery_results')
    op.drop_table('ai_analysis')
    op.drop_table('fragments')
    op.drop_table('files')
    op.drop_table('recovery_jobs')
    op.drop_table('users')
