"""
SentinelSIEM Legacy Authentication Audit Compatibility Layer
=============================================================

DEPRECATED
==========

This module exists only for backward compatibility with legacy
authentication and authorization components.

Canonical audit architecture
----------------------------

All new audit functionality MUST use:

    app.audit

The centralized audit domain owns:

    - canonical audit models
    - audit validation
    - audit persistence
    - audit querying
    - global audit
    - user-scoped audit
    - audit service orchestration

Canonical persistence source:

    siem_auth_audit

Compatibility contract
----------------------

Older authentication/authorization code may still import:

    AuditRecord
    AuditSink
    InMemoryAuditSink
    AuditValidationError
    validate_audit_record
    validate
    LegacyAuditRepositoryAdapter

These names are preserved for compatibility.

IMPORTANT
---------

The legacy authentication layer historically used:

    app.auth.models.AuditRecord

The canonical audit domain uses:

    app.audit.models.AuditEvent

Those are NOT the same runtime type.

This compatibility layer therefore performs an explicit:

    legacy AuditRecord
            ->
    canonical AuditEvent

conversion before canonical validation/persistence.

Security
--------

Audit records must never intentionally contain:

    - plaintext passwords
    - password hashes
    - access tokens
    - refresh tokens
    - JWT contents
    - JWT/token identifiers
    - API keys
    - client secrets
    - private keys
    - session secrets
    - credentials

Production persistence remains owned by app.audit.

Transaction ownership
---------------------

This compatibility layer does not commit database transactions.

Database transaction boundaries remain owned by the caller/service/
application layer and the canonical audit repository.

Migration direction
-------------------

Legacy:

    app.auth.audit
            |
            v

Canonical:

    app.audit
"""

from __future__ import annotations

import warnings
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any, Final, Protocol, runtime_checkable
from uuid import UUID

from app.audit.models import AuditEvent
from app.audit.repository import (
    AuditRepository,
    AuditRepositoryError,
    AuditRepositoryValidationError,
)
from app.auth.models import AuditRecord as LegacyAuditRecord

# ============================================================================
# Compatibility types
# ============================================================================

#
# IMPORTANT:
#
# Do NOT alias this to app.audit.models.AuditEvent.
#
# Legacy AuthorizationService creates:
#
#     app.auth.models.AuditRecord
#
# and passes that object into AuditSink.
#
# Keeping the legacy type here allows the compatibility layer to accept it
# and explicitly translate it into the canonical AuditEvent representation.
#

type AuditRecord = LegacyAuditRecord


# ============================================================================
# Compatibility errors
# ============================================================================

#
# Older callers expect AuditValidationError.
#
# The canonical repository owns the validation exception.
#

AuditValidationError = AuditRepositoryValidationError


# ============================================================================
# Deprecation
# ============================================================================

_DEPRECATION_MESSAGE: Final[str] = (
    "app.auth.audit is deprecated. Use app.audit for centralized audit functionality."
)


def _warn_deprecated() -> None:
    """
    Emit the legacy-module deprecation warning.
    """
    warnings.warn(
        _DEPRECATION_MESSAGE,
        DeprecationWarning,
        stacklevel=3,
    )


# ============================================================================
# Audit sink protocol
# ============================================================================


@runtime_checkable
class AuditSinkProtocol(Protocol):
    """
    Structural protocol for legacy audit sinks.

    Legacy authentication/authorization components only require a
    synchronous record(event) operation.
    """

    def record(self, event: AuditRecord) -> None:
        """
        Record one legacy audit event.
        """
        ...


# ============================================================================
# Legacy audit sink
# ============================================================================


class AuditSink:
    """
    Deprecated compatibility audit sink.

    This base class does not persist anything.

    New production code should use the centralized audit service/repository
    under app.audit.
    """

    def __init__(self) -> None:
        """
        Initialize the compatibility sink.

        The base implementation intentionally stores nothing.
        """
        _warn_deprecated()

    def record(self, event: AuditRecord) -> None:
        """
        Legacy synchronous audit recording contract.

        Subclasses must implement this method.
        """
        raise NotImplementedError(
            "Legacy AuditSink is deprecated. Use app.audit for centralized audit persistence."
        )


# ============================================================================
# Canonical field helpers
# ============================================================================


def _first_present(
    source: object,
    *names: str,
    default: Any = None,
) -> Any:
    """
    Return the first available attribute/key from an object or mapping.
    """
    if isinstance(source, Mapping):
        for name in names:
            if name in source:
                return source[name]
        return default

    for name in names:
        if hasattr(source, name):
            return getattr(source, name)

    return default


def _normalize_uuid(value: object) -> UUID | None:
    """
    Normalize UUID-like values for canonical AuditEvent construction.

    Returns None when the value is absent.

    Raises AuditValidationError when a non-empty invalid UUID value is
    supplied.
    """
    if value is None:
        return None

    if isinstance(value, UUID):
        return value

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

        try:
            return UUID(value)
        except ValueError as exc:
            raise AuditValidationError(f"invalid UUID audit identifier: {value!r}") from exc

    raise AuditValidationError(f"invalid UUID audit identifier type: {type(value).__name__}")


def _normalize_timestamp(value: object) -> datetime | None:
    """
    Normalize the legacy timestamp into a timezone-aware datetime.

    Canonical audit events use created_at.

    Legacy authentication events historically used timestamp.
    """
    if value is None:
        return None

    if not isinstance(value, datetime):
        raise AuditValidationError("audit timestamp must be a datetime.")

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)

    return value


def _normalize_metadata(value: object) -> dict[str, object]:
    """
    Normalize audit metadata into a plain dictionary.

    None becomes an empty dictionary.

    A non-mapping metadata value is rejected because canonical audit
    metadata is structured JSON.
    """
    if value is None:
        return {}

    if not isinstance(value, Mapping):
        raise AuditValidationError("audit metadata must be a mapping.")

    return dict(value)


# ============================================================================
# Security metadata validation
# ============================================================================


_FORBIDDEN_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "password_hash",
        "hashed_password",
        "access_token",
        "refresh_token",
        "id_token",
        "jwt",
        "token",
        "token_id",
        "jti",
        "api_key",
        "apikey",
        "client_secret",
        "secret",
        "private_key",
        "privatekey",
        "session_secret",
        "session_token",
        "credential",
        "credentials",
        "authorization",
        "cookie",
    }
)


def _normalize_metadata_key(key: object) -> str:
    """
    Normalize a metadata key for security comparison.

    Examples:

        Access-Token -> access_token
        PASSWORD    -> password
        " session secret " -> session_secret
    """
    return str(key).strip().lower().replace("-", "_").replace(" ", "_")


def _validate_safe_metadata(
    value: object,
    path: str = "metadata_json",
) -> None:
    """
    Recursively validate audit metadata.

    Credential material is rejected even when nested inside dictionaries,
    lists, tuples, or sets.
    """

    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            normalized_key = _normalize_metadata_key(key)

            if normalized_key in _FORBIDDEN_METADATA_KEYS:
                raise AuditValidationError(
                    f"Sensitive credential field '{path}.{key}' is not permitted in audit metadata."
                )

            _validate_safe_metadata(
                nested_value,
                path=f"{path}.{key}",
            )

        return

    if isinstance(value, (list, tuple, set, frozenset)):
        for index, nested_value in enumerate(value):
            _validate_safe_metadata(
                nested_value,
                path=f"{path}[{index}]",
            )

        return


# ============================================================================
# Legacy -> canonical conversion
# ============================================================================


def _to_canonical_audit_event(
    event: AuditRecord | AuditEvent,
) -> AuditEvent:
    """
    Convert a legacy authentication AuditRecord into the canonical
    app.audit.models.AuditEvent.

    If the caller already supplies an AuditEvent, it is returned unchanged.

    This function is the central compatibility boundary between:

        app.auth
            and
        app.audit
    """

    # ------------------------------------------------------------------------
    # Already canonical
    # ------------------------------------------------------------------------

    if isinstance(event, AuditEvent):
        return event

    # ------------------------------------------------------------------------
    # Legacy event validation
    # ------------------------------------------------------------------------

    if not isinstance(event, LegacyAuditRecord):
        raise AuditValidationError("audit event must be an AuditRecord or AuditEvent instance.")

    # ------------------------------------------------------------------------
    # Read legacy fields
    # ------------------------------------------------------------------------

    action = _first_present(
        event,
        "action",
        default=None,
    )

    outcome = _first_present(
        event,
        "outcome",
        default=None,
    )

    actor_user_id = _first_present(
        event,
        "actor_user_id",
        default=None,
    )

    target_user_id = _first_present(
        event,
        "target_user_id",
        default=None,
    )

    session_id = _first_present(
        event,
        "session_id",
        default=None,
    )

    request_id = _first_present(
        event,
        "request_id",
        default=None,
    )

    source_ip = _first_present(
        event,
        "source_ip",
        default=None,
    )

    metadata = _first_present(
        event,
        "metadata_json",
        "metadata",
        default=None,
    )

    timestamp = _first_present(
        event,
        "timestamp",
        "created_at",
        default=None,
    )

    # ------------------------------------------------------------------------
    # Normalize values
    # ------------------------------------------------------------------------

    if not isinstance(action, str) or not action.strip():
        raise AuditValidationError("audit action must be a non-empty string.")

    if not isinstance(outcome, str) or not outcome.strip():
        raise AuditValidationError("audit outcome must be a non-empty string.")

    normalized_metadata = _normalize_metadata(metadata)

    _validate_safe_metadata(normalized_metadata)

    normalized_actor_user_id = _normalize_uuid(actor_user_id)
    normalized_target_user_id = _normalize_uuid(target_user_id)

    normalized_session_id = str(session_id).strip() if session_id is not None else None

    normalized_request_id = str(request_id).strip() if request_id is not None else None

    normalized_source_ip = str(source_ip).strip() if source_ip is not None else None

    normalized_timestamp = _normalize_timestamp(timestamp)

    # ------------------------------------------------------------------------
    # Build canonical event
    # ------------------------------------------------------------------------
    #
    # AuditEvent is a Pydantic/ORM canonical domain object in SentinelSIEM.
    # The constructor is intentionally kept explicit rather than using
    # model_dump/vars so sensitive or legacy-only fields cannot accidentally
    # cross the compatibility boundary.
    #

    values: dict[str, Any] = {
        "action": action.strip(),
        "outcome": outcome.strip(),
        "actor_user_id": normalized_actor_user_id,
        "target_user_id": normalized_target_user_id,
        "session_id": normalized_session_id,
        "request_id": normalized_request_id,
        "source_ip": normalized_source_ip,
        "metadata_json": normalized_metadata,
    }

    if normalized_timestamp is not None:
        #
        # Canonical model uses created_at.
        #
        values["created_at"] = normalized_timestamp

    try:
        return AuditEvent(**values)

    except Exception as exc:
        #
        # Do not leak arbitrary constructor internals through the
        # compatibility boundary.
        #
        raise AuditValidationError(f"invalid canonical audit event: {exc}") from exc


# ============================================================================
# Canonical validation
# ============================================================================


def validate_audit_record(
    event: AuditRecord | AuditEvent,
) -> None:
    """
    Validate a legacy or canonical audit event.

    Legacy AuditRecord objects are converted to AuditEvent first.

    The centralized audit repository remains the canonical source of truth
    for persistence validation. This function exists because older
    authentication tests/callers expect a callable named
    validate_audit_record().
    """

    canonical_event = _to_canonical_audit_event(event)

    # ------------------------------------------------------------------------
    # Basic classification validation
    # ------------------------------------------------------------------------

    action = getattr(canonical_event, "action", None)
    outcome = getattr(canonical_event, "outcome", None)

    if not isinstance(action, str) or not action.strip():
        raise AuditValidationError("audit action must be a non-empty string.")

    if not isinstance(outcome, str) or not outcome.strip():
        raise AuditValidationError("audit outcome must be a non-empty string.")

    # ------------------------------------------------------------------------
    # Metadata protection
    # ------------------------------------------------------------------------

    metadata = getattr(
        canonical_event,
        "metadata_json",
        None,
    )

    if metadata is not None:
        _validate_safe_metadata(metadata)

    # ------------------------------------------------------------------------
    # Canonical repository validation
    # ------------------------------------------------------------------------
    #
    # Keep this optional and defensive.
    #
    # Different SentinelSIEM repository revisions expose validation either
    # as a module-level function or through repository internals. The
    # compatibility layer therefore performs the security-critical checks
    # above without requiring an unstable repository instance/API.
    #


# ============================================================================
# Backward-compatible validate alias
# ============================================================================


def validate(
    event: AuditRecord | AuditEvent,
) -> None:
    """
    Backward-compatible alias for validate_audit_record().
    """
    validate_audit_record(event)


# ============================================================================
# Legacy in-memory audit sink
# ============================================================================


class InMemoryAuditSink(AuditSink):
    """
    Deprecated in-memory compatibility sink.

    This implementation is intentionally non-persistent.

    It exists for:

        - legacy unit tests
        - authentication tests
        - authorization tests
        - local compatibility scenarios

    It MUST NOT be used for production audit persistence.

    Production persistence belongs to:

        app.audit
            +
        AuditRepository
            +
        siem_auth_audit
    """

    def __init__(
        self,
        events: Iterable[AuditRecord | AuditEvent] | None = None,
    ) -> None:
        """
        Initialize the in-memory compatibility sink.

        Args:
            events:
                Optional initial events, primarily useful for tests.
        """

        #
        # Do not call AuditSink.__init__().
        #
        # That would emit a deprecation warning for every test-created
        # in-memory sink.
        #

        self._events: list[AuditRecord | AuditEvent] = []

        if events is not None:
            for event in events:
                self.record(event)

    def record(
        self,
        event: AuditRecord | AuditEvent,
    ) -> None:
        """
        Validate and store one audit event in memory.

        IMPORTANT:

        The legacy event remains available to callers exactly as supplied.

        Validation additionally constructs the canonical AuditEvent so that
        compatibility events are guaranteed to satisfy the centralized
        audit-domain contract.
        """

        #
        # This validates both:
        #
        #     LegacyAuditRecord
        #
        # and:
        #
        #     AuditEvent
        #
        validate_audit_record(event)

        self._events.append(event)

    def all(
        self,
    ) -> tuple[AuditRecord | AuditEvent, ...]:
        """
        Return an immutable snapshot of all stored events.
        """
        return tuple(self._events)

    def latest(
        self,
    ) -> AuditRecord | AuditEvent | None:
        """
        Return the latest stored event.

        Returns:
            The most recently recorded event, or None if empty.
        """
        if not self._events:
            return None

        return self._events[-1]

    def count(self) -> int:
        """
        Return the number of stored events.
        """
        return len(self._events)

    def clear(self) -> None:
        """
        Clear all in-memory events.

        This method exists exclusively for tests and compatibility use.
        """
        self._events.clear()

    def __len__(self) -> int:
        """
        Return the number of stored events.
        """
        return len(self._events)

    def __iter__(self):
        """
        Iterate over a snapshot of stored events.
        """
        return iter(tuple(self._events))


# ============================================================================
# Canonical repository adapter
# ============================================================================


class LegacyAuditRepositoryAdapter:
    """
    Compatibility adapter for callers that still produce legacy
    app.auth.models.AuditRecord instances.

    This adapter converts legacy events to canonical AuditEvent instances
    before handing them to AuditRepository.

    The adapter never owns transaction boundaries.
    """

    def __init__(
        self,
        repository: AuditRepository,
    ) -> None:
        self._repository = repository

    def record(
        self,
        event: AuditRecord | AuditEvent,
    ) -> Any:
        """
        Convert and persist an audit event through the canonical repository.

        No database transaction is committed here.
        """

        canonical_event = _to_canonical_audit_event(event)

        validate_audit_record(canonical_event)

        #
        # Repository APIs can evolve independently from this deprecated
        # compatibility layer. Prefer the canonical record/create method
        # when available.
        #

        record_method = getattr(
            self._repository,
            "record",
            None,
        )

        if callable(record_method):
            return record_method(canonical_event)

        create_method = getattr(
            self._repository,
            "create",
            None,
        )

        if callable(create_method):
            return create_method(canonical_event)

        raise AuditRepositoryError(
            "AuditRepository does not expose a supported record/create method."
        )


# ============================================================================
# Convenience conversion API
# ============================================================================


def to_audit_event(
    event: AuditRecord | AuditEvent,
) -> AuditEvent:
    """
    Public compatibility helper.

    Convert a legacy AuditRecord into the canonical AuditEvent.

    Canonical AuditEvent instances are returned unchanged.
    """
    return _to_canonical_audit_event(event)


# ============================================================================
# Public API
# ============================================================================


__all__ = [
    "AuditRecord",
    "AuditSink",
    "AuditSinkProtocol",
    "InMemoryAuditSink",
    "AuditValidationError",
    "LegacyAuditRepositoryAdapter",
    "validate_audit_record",
    "validate",
    "to_audit_event",
]
