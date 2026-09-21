"""rename audit metadata column

Revision ID: f4c833262130
Revises: 5cf4190df62b
Create Date: 2026-08-29 19:24:59.576848

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f4c833262130"
down_revision: Union[str, Sequence[str], None] = "5cf4190df62b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Rename the canonical audit metadata column."""

    op.alter_column(
        "siem_auth_audit",
        "metadata",
        new_column_name="metadata_json",
    )


def downgrade() -> None:
    """Restore the previous audit metadata column name."""

    op.alter_column(
        "siem_auth_audit",
        "metadata_json",
        new_column_name="metadata",
    )
