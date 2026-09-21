"""align audit varchar lengths with orm model

Revision ID: 9f7eb6d04258
Revises: f4c833262130
Create Date: 2026-09-01 09:28:25.647384

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "9f7eb6d04258"
down_revision: Union[str, Sequence[str], None] = "f4c833262130"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Align audit VARCHAR lengths with the AuditEvent ORM model."""

    op.alter_column(
        "siem_auth_audit",
        "action",
        existing_type=sa.String(length=128),
        type_=sa.String(length=150),
        existing_nullable=False,
    )

    op.alter_column(
        "siem_auth_audit",
        "outcome",
        existing_type=sa.String(length=32),
        type_=sa.String(length=50),
        existing_nullable=False,
    )

    op.alter_column(
        "siem_auth_audit",
        "request_id",
        existing_type=sa.String(length=128),
        type_=sa.String(length=100),
        existing_nullable=True,
    )


def downgrade() -> None:
    """Restore the previous audit VARCHAR lengths."""

    op.alter_column(
        "siem_auth_audit",
        "request_id",
        existing_type=sa.String(length=100),
        type_=sa.String(length=128),
        existing_nullable=True,
    )

    op.alter_column(
        "siem_auth_audit",
        "outcome",
        existing_type=sa.String(length=50),
        type_=sa.String(length=32),
        existing_nullable=False,
    )

    op.alter_column(
        "siem_auth_audit",
        "action",
        existing_type=sa.String(length=150),
        type_=sa.String(length=128),
        existing_nullable=False,
    )
