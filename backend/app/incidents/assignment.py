from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from app.incidents.models import Incident


# ============================================================================
# Incident Assignment
# ============================================================================


class IncidentAssignment:
    """
    Apply Incident assignee changes.

    Assignment responsibilities are intentionally limited to the Incident
    domain mutation itself.

    User existence, active/locked state, and role validation are handled by
    the application/API boundary through User Management.

    The Incident domain stores only the assigned user's UUID.
    """

    # ------------------------------------------------------------------------
    # Assign / Reassign
    # ------------------------------------------------------------------------

    @staticmethod
    def assign(
        incident: Incident,
        *,
        assignee: UUID | None,
    ) -> Incident:
        """
        Assign or reassign an Incident.

        Args:
            incident:
                Existing immutable Incident aggregate.

            assignee:
                User UUID to assign the Incident to.
                ``None`` intentionally leaves the Incident unassigned.

        Returns:
            A new immutable Incident with the updated assignee.

        Raises:
            ValueError:
                If ``incident`` is not a valid Incident or ``assignee`` is
                neither a UUID nor None.
        """

        if not isinstance(incident, Incident):
            raise ValueError(
                "incident must be a valid Incident"
            )

        if assignee is not None and not isinstance(assignee, UUID):
            raise ValueError(
                "assignee must be a valid user UUID or None"
            )

        return incident.model_copy(
            update={
                "assigned_to": assignee,
                "updated_at": datetime.now(UTC),
            }
        )

    # ------------------------------------------------------------------------
    # Unassign
    # ------------------------------------------------------------------------

    @staticmethod
    def unassign(
        incident: Incident,
    ) -> Incident:
        """
        Remove the current Incident assignee.

        The Incident remains persisted and its historical audit record is
        created by the application/manager layer.
        """

        if not isinstance(incident, Incident):
            raise ValueError(
                "incident must be a valid Incident"
            )

        return incident.model_copy(
            update={
                "assigned_to": None,
                "updated_at": datetime.now(UTC),
            }
        )


# ============================================================================
# Public API
# ============================================================================


__all__ = [
    "IncidentAssignment",
]