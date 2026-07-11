"""Initial schema — all tables

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-07-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── users ──────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.Text, nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("is_verified", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("api_key_hash", sa.Text, nullable=True),
        sa.Column("api_key_prefix", sa.String(16), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"])

    # ── cloud_accounts ─────────────────────────────────────────────────────────
    op.create_table(
        "cloud_accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        # AWS
        sa.Column("aws_account_id", sa.String(20), nullable=True),
        sa.Column("aws_role_arn", sa.Text, nullable=True),
        sa.Column("aws_regions", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        # GCP
        sa.Column("gcp_project_id", sa.String(255), nullable=True),
        sa.Column("gcp_service_account_email", sa.Text, nullable=True),
        # Azure
        sa.Column("azure_subscription_id", sa.String(100), nullable=True),
        sa.Column("azure_tenant_id", sa.String(100), nullable=True),
        # Metadata
        sa.Column("last_scanned_at", sa.String(50), nullable=True),
        sa.Column("scan_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("credentials_valid", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("last_validation_error", sa.Text, nullable=True),
        # FK
        sa.Column("owner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_cloud_accounts_provider", "cloud_accounts", ["provider"])
    op.create_index("ix_cloud_accounts_owner_id", "cloud_accounts", ["owner_id"])

    # ── scans ──────────────────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("scan_type", sa.String(50), nullable=False, server_default="full"),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer, nullable=True),
        sa.Column("total_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("critical_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("high_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("medium_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("low_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("info_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Float, nullable=True),
        sa.Column("scan_config", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("services_scanned", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("resources_scanned", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("progress", sa.Integer, nullable=False, server_default="0"),
        # FKs
        sa.Column("cloud_account_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("initiated_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_cloud_account_id", "scans", ["cloud_account_id"])

    # ── findings ───────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("rule_id", sa.String(100), nullable=False),
        sa.Column("rule_name", sa.String(500), nullable=False),
        sa.Column("rule_description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cvss_vector", sa.String(200), nullable=True),
        sa.Column("resource_id", sa.String(500), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=False),
        sa.Column("resource_name", sa.String(500), nullable=True),
        sa.Column("resource_arn", sa.Text, nullable=True),
        sa.Column("region", sa.String(100), nullable=True),
        sa.Column("cloud_provider", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("is_suppressed", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("suppression_reason", sa.Text, nullable=True),
        sa.Column("evidence", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("affected_asset", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("cis_benchmark_refs", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("mitre_attack_techniques", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("compliance_frameworks", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("remediation_steps", sa.Text, nullable=True),
        sa.Column("remediation_code", sa.Text, nullable=True),
        sa.Column("ai_explanation", sa.Text, nullable=True),
        sa.Column("ai_remediation", sa.Text, nullable=True),
        # FK
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_resource_type", "findings", ["resource_type"])
    op.create_index("ix_findings_cloud_provider", "findings", ["cloud_provider"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])

    # ── reports ────────────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="generating"),
        sa.Column("format", sa.String(20), nullable=False, server_default="pdf"),
        sa.Column("s3_key", sa.Text, nullable=True),
        sa.Column("s3_url", sa.Text, nullable=True),
        sa.Column("file_size_bytes", sa.Integer, nullable=True),
        sa.Column("report_metadata", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("summary", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        # FKs
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("generated_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("cloud_accounts")
    op.drop_table("users")
