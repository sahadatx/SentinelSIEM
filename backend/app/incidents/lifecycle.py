from __future__ import annotations

from datetime import UTC, datetime

from app.incidents.models import (
    Incident,
    IncidentAuditEntry,
    IncidentStatus,
)


# ============================================================================
# Canonical Incident Lifecycle
# ============================================================================
#
# OPEN
#   ↓
# INVESTIGATING
#   ↓
# CONTAINED
#   ↓
# RESOLVED
#   ↓
# CLOSED
#
# The lifecycle is intentionally strict.
# Invalid transitions are rejected by the backend.
# ============================================================================


_ALLOWED_TRANSITIONS: dict[
    IncidentStatus,
    frozenset[IncidentStatus],
] = {
    IncidentStatus.OPEN: frozenset(
        {
            IncidentStatus.INVESTIGATING,
        }
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.CONTAINED,
        }
    ),
    IncidentStatus.CONTAINED: frozenset(
        {
            IncidentStatus.RESOLVED,
        }
    ),
    IncidentStatus.RESOLVED: frozenset(
        {
            IncidentStatus.CLOSED,
        }
    ),
    IncidentStatus.CLOSED: frozenset(),
}


# ============================================================================
# Incident Lifecycle
# ============================================================================


class IncidentLifecycle:
    """
    Validate and apply canonical Incident lifecycle transitions.

    Lifecycle:

        OPEN
          ↓
        INVESTIGATING
          ↓
        CONTAINED
          ↓
        RESOLVED
          ↓
        CLOSED

    All lifecycle validation is performed server-side.
    """

    # ------------------------------------------------------------------------
    # Allowed transitions
    # ------------------------------------------------------------------------

    @staticmethod
    def allowed_transitions(
        status: IncidentStatus,
    ) -> frozenset[IncidentStatus]:
        """
        Return the lifecycle states allowed from the given status.

        Unknown values return an empty transition set rather than allowing
        an implicit transition.
        """

        if not isinstance(status, IncidentStatus):
            return frozenset()

        return _ALLOWED_TRANSITIONS.get(
            status,
            frozenset(),
        )

    # ------------------------------------------------------------------------
    # Transition validation
    # ------------------------------------------------------------------------

    @classmethod
    def can_transition(
        cls,
        incident: Incident,
        target: IncidentStatus,
    ) -> bool:
        """
        Return whether the requested lifecycle transition is valid.
        """

        if not isinstance(incident, Incident):
            return False

        if not isinstance(target, IncidentStatus):
            return False

        return target in cls.allowed_transitions(
            incident.status,
        )

    # ------------------------------------------------------------------------
    # Apply transition
    # ------------------------------------------------------------------------

    @classmethod
    def transition(
        cls,
        incident: Incident,
        target: IncidentStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> tuple[Incident, IncidentAuditEntry]:
        """
        Validate and apply one Incident lifecycle transition.

        Returns:
            A tuple containing:

            1. The updated immutable Incident.
            2. The corresponding immutable audit entry.

        Raises:
            ValueError:
                If actor is empty, target is invalid, or the requested
                lifecycle transition is not permitted.
        """

        # --------------------------------------------------------------------
        # Validate incident
        # --------------------------------------------------------------------

        if not isinstance(incident, Incident):
            raise ValueError("incident must be a valid Incident")

        # --------------------------------------------------------------------
        # Validate target
        # --------------------------------------------------------------------

        if not isinstance(target, IncidentStatus):
            raise ValueError(
                "target must be a valid IncidentStatus"
            )

        # --------------------------------------------------------------------
        # Validate actor
        # --------------------------------------------------------------------

        normalized_actor = actor.strip()

        if not normalized_actor:
            raise ValueError("actor is required")

        # --------------------------------------------------------------------
        # Normalize reason
        # --------------------------------------------------------------------

        normalized_reason = reason.strip()

        # --------------------------------------------------------------------
        # Validate lifecycle transition
        # --------------------------------------------------------------------

        if not cls.can_transition(
            incident,
            target,
        ):
            raise ValueError(
                "invalid incident transition: "
                f"{incident.status.value} -> {target.value}"
            )

        # --------------------------------------------------------------------
        # Timestamp
        # --------------------------------------------------------------------

        now = datetime.now(UTC)

        # --------------------------------------------------------------------
        # Build immutable Incident update
        # --------------------------------------------------------------------

        update: dict[str, object] = {
            "status": target,
            "updated_at": now,
        }

        # --------------------------------------------------------------------
        # Lifecycle-specific timestamps
        # --------------------------------------------------------------------

        if target == IncidentStatus.RESOLVED:
            update["resolved_at"] = now

        elif target == IncidentStatus.CLOSED:
            update["closed_at"] = now

        # --------------------------------------------------------------------
        # Apply immutable update
        # --------------------------------------------------------------------

        updated = incident.model_copy(
            update=update,
        )

        # --------------------------------------------------------------------
        # Create audit record
        # --------------------------------------------------------------------

        audit = IncidentAuditEntry(
            incident_id=incident.incident_id,
            action="incident_status_changed",
            actor=normalized_actor,
            from_status=incident.status,
            to_status=target,
            reason=normalized_reason,
            created_at=now,
        )

        return updated, audit


# ============================================================================
# Public API
# ============================================================================


__all__ = [
    "IncidentLifecycle",
]