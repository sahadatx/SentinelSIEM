"""align audit id with uuid model

Revision ID: 5cf4190df62b
Revises: 6f5016b46eea
Create Date: 2026-08-29 19:08:57.283759

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "5cf4190df62b"
down_revision: Union[str, Sequence[str], None] = "6f5016b46eea"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Convert siem_auth_audit.audit_id from BIGINT to UUID."""

    # PostgreSQL's uuid_generate_v4() requires the uuid-ossp
    # extension. pgcrypto is more commonly available in
    # PostgreSQL installations and provides gen_random_uuid().
    op.execute(
        "CREATE EXTENSION IF NOT EXISTS pgcrypto"
    )

    # Remove the old BIGINT sequence default.
    op.alter_column(
        "siem_auth_audit",
        "audit_id",
        server_default=None,
    )

    # Remove the existing BIGINT primary key constraint.
    op.drop_constraint(
        "siem_auth_audit_pkey",
        "siem_auth_audit",
        type_="primary",
    )

    # Convert existing BIGINT identifiers into newly generated UUIDs.
    #
    # We intentionally generate UUIDs for existing records rather than
    # attempting to cast BIGINT values directly to UUID.
    op.add_column(
        "siem_auth_audit",
        sa.Column(
            "audit_id_uuid",
            sa.UUID(),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE siem_auth_audit
        SET audit_id_uuid = gen_random_uuid()
        WHERE audit_id_uuid IS NULL
        """
    )

    # Existing rows now have UUID identifiers.
    op.alter_column(
        "siem_auth_audit",
        "audit_id_uuid",
        nullable=False,
    )

    # Remove the old BIGINT audit_id.
    op.drop_column(
        "siem_auth_audit",
        "audit_id",
    )

    # Rename the UUID column to the canonical model field name.
    op.alter_column(
        "siem_auth_audit",
        "audit_id_uuid",
        new_column_name="audit_id",
    )

    # Restore the primary key using UUID.
    op.create_primary_key(
        "siem_auth_audit_pkey",
        "siem_auth_audit",
        ["audit_id"],
    )

    # Remove the obsolete BIGINT sequence.
    op.execute(
        """
        DROP SEQUENCE IF EXISTS
        siem_auth_audit_audit_id_seq
        """
    )


def downgrade() -> None:
    """Convert siem_auth_audit.audit_id from UUID back to BIGINT."""

    # Remove UUID primary key.
    op.drop_constraint(
        "siem_auth_audit_pkey",
        "siem_auth_audit",
        type_="primary",
    )

    # Create temporary BIGINT identifier column.
    op.add_column(
        "siem_auth_audit",
        sa.Column(
            "audit_id_bigint",
            sa.BigInteger(),
            nullable=True,
        ),
    )

    # Generate deterministic sequential BIGINT identifiers.
    op.execute(
        """
        WITH numbered AS (
            SELECT
                audit_id,
                ROW_NUMBER() OVER (
                    ORDER BY created_at, audit_id
                ) AS new_id
            FROM siem_auth_audit
        )
        UPDATE siem_auth_audit AS a
        SET audit_id_bigint = numbered.new_id
        FROM numbered
        WHERE a.audit_id = numbered.audit_id
        """
    )

    op.alter_column(
        "siem_auth_audit",
        "audit_id_bigint",
        nullable=False,
    )

    # Remove UUID identifier.
    op.drop_column(
        "siem_auth_audit",
        "audit_id",
    )

    # Restore canonical BIGINT field name.
    op.alter_column(
        "siem_auth_audit",
        "audit_id_bigint",
        new_column_name="audit_id",
    )

    # Restore BIGINT sequence.
    op.execute(
        """
        CREATE SEQUENCE siem_auth_audit_audit_id_seq
        """
    )

    # Make the sequence continue after the highest existing ID.
    op.execute(
        """
        SELECT setval(
            'siem_auth_audit_audit_id_seq',
            COALESCE(
                (SELECT MAX(audit_id)
                 FROM siem_auth_audit),
                1
            ),
            true
        )
        """
    )

    # Restore sequence-backed default.
    op.alter_column(
        "siem_auth_audit",
        "audit_id",
        server_default=sa.text(
            "nextval('siem_auth_audit_audit_id_seq'::regclass)"
        ),
    )

    # Restore primary key.
    op.create_primary_key(
        "siem_auth_audit_pkey",
        "siem_auth_audit",
        ["audit_id"],
    )
