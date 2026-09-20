from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import String, case, cast, func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.models import AuditEvent
from app.audit.schemas import AuditCreate


# =============================================================================
# Constants
# =============================================================================

DEFAULT_PAGE: Final[int] = 1
DEFAULT_PAGE_SIZE: Final[int] = 50
MAX_PAGE_SIZE: Final[int] = 200

DEFAULT_USER_EVENTS_LIMIT: Final[int] = 100
MAX_USER_EVENTS_LIMIT: Final[int] = 200

DEFAULT_RELATED_LIMIT: Final[int] = 100
MAX_RELATED_LIMIT: Final[int] = 200

DEFAULT_EXPORT_LIMIT: Final[int] = 10_000
MAX_EXPORT_LIMIT: Final[int] = 50_000

MAX_REQUEST_ID_LENGTH: Final[int] = 100
MAX_SOURCE_IP_LENGTH: Final[int] = 45

MAX_METADATA_DEPTH: Final[int] = 10

CANONICAL_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
        "success",
        "failure",
        "denied",
    }
)


# =============================================================================
# Exceptions
# =============================================================================


class AuditRepositoryError(RuntimeError):
    """
    Base exception for audit repository failures.
    """


class AuditRepositoryValidationError(AuditRepositoryError):
    """
    Raised when repository input violates the audit contract.
    """


AuditValidationError = AuditRepositoryValidationError


# =============================================================================
# Sensitive Metadata Protection
# =============================================================================


_SENSITIVE_METADATA_KEYS: Final[frozenset[str]] = frozenset(
    {
        # Password material
        "password",
        "passwd",
        "passphrase",
        "pwd",
        "password_hash",
        "password_hash_value",
        "hashed_password",
        "hash_password",
        "new_password",
        "current_password",
        "old_password",
        "plaintext_password",
        "plain_password",
        "password_value",
        "user_password",

        # Token material
        "token",
        "token_id",
        "token_value",
        "access_token",
        "access_token_value",
        "refresh_token",
        "refresh_token_value",
        "session_token",
        "session_token_value",
        "bearer_token",
        "bearer_token_value",
        "jwt",
        "jwt_token",
        "jwt_token_value",
        "jwt_value",
        "id_token",

        # API/client credentials
        "api_key",
        "api_key_value",
        "client_secret",
        "client_secret_value",

        # Secrets
        "secret",
        "secret_key",
        "secret_value",
        "session_secret",
        "session_secret_value",

        # Cryptographic material
        "private_key",
        "private_key_value",
        "encryption_key",
        "encryption_key_value",
        "signing_key",
        "signing_key_value",

        # HTTP authentication
        "authorization",
        "authorization_header",
        "authorization_token",
        "auth_header",

        # Cookies
        "cookie",
        "cookies",
        "set_cookie",

        # Generic credentials
        "credential",
        "credentials",
        "credential_material",
        "credential_value",
        "user_credentials",
    }
)


# =============================================================================
# Metadata Key Normalization
# =============================================================================


def _normalize_metadata_key(
    key: object,
) -> str:
    """
    Normalize metadata keys to canonical snake_case.
    """

    normalized = str(key).strip()

    normalized = re.sub(
        r"([a-z0-9])([A-Z])",
        r"\1_\2",
        normalized,
    )

    normalized = re.sub(
        r"([A-Z]+)([A-Z][a-z])",
        r"\1_\2",
        normalized,
    )

    normalized = normalized.lower()

    normalized = re.sub(
        r"[-\s./\\]+",
        "_",
        normalized,
    )

    normalized = re.sub(
        r"_+",
        "_",
        normalized,
    )

    normalized = normalized.strip("_")

    compact_aliases: dict[str, str] = {
        "passwordhash": "password_hash",
        "passwordhashvalue": "password_hash_value",
        "hashedpassword": "hashed_password",
        "hashpassword": "hash_password",
        "newpassword": "new_password",
        "currentpassword": "current_password",
        "oldpassword": "old_password",
        "plaintextpassword": "plaintext_password",
        "plainpassword": "plain_password",
        "passwordvalue": "password_value",
        "userpassword": "user_password",

        "tokenid": "token_id",
        "tokenvalue": "token_value",

        "accesstoken": "access_token",
        "accesstokenvalue": "access_token_value",

        "refreshtoken": "refresh_token",
        "refreshtokenvalue": "refresh_token_value",

        "sessiontoken": "session_token",
        "sessiontokenvalue": "session_token_value",

        "bearertoken": "bearer_token",
        "bearertokenvalue": "bearer_token_value",

        "jwttoken": "jwt_token",
        "jwttokenvalue": "jwt_token_value",
        "jwtvalue": "jwt_value",

        "idtoken": "id_token",

        "apikey": "api_key",
        "apikeyvalue": "api_key_value",

        "clientsecret": "client_secret",
        "clientsecretvalue": "client_secret_value",

        "secretkey": "secret_key",
        "secretvalue": "secret_value",

        "sessionsecret": "session_secret",
        "sessionsecretvalue": "session_secret_value",

        "privatekey": "private_key",
        "privatekeyvalue": "private_key_value",

        "encryptionkey": "encryption_key",
        "encryptionkeyvalue": "encryption_key_value",

        "signingkey": "signing_key",
        "signingkeyvalue": "signing_key_value",

        "authorizationheader": "authorization_header",
        "authorizationtoken": "authorization_token",
        "authheader": "auth_header",

        "setcookie": "set_cookie",

        "credentialmaterial": "credential_material",
        "credentialvalue": "credential_value",
        "usercredentials": "user_credentials",
    }

    return compact_aliases.get(
        normalized,
        normalized,
    )


def _is_sensitive_metadata_key(
    key: object,
) -> bool:
    """
    Return True when a metadata key contains forbidden credential material.
    """

    return (
        _normalize_metadata_key(key)
        in _SENSITIVE_METADATA_KEYS
    )


# =============================================================================
# Recursive Metadata Validation
# =============================================================================


def _validate_safe_metadata(
    value: Any,
    *,
    path: str = "metadata_json",
    depth: int = 0,
) -> None:
    """
    Recursively validate audit metadata.
    """

    if depth > MAX_METADATA_DEPTH:
        raise AuditRepositoryValidationError(
            "Audit metadata exceeds the maximum supported "
            f"nesting depth of {MAX_METADATA_DEPTH}."
        )

    if isinstance(value, dict):
        for key, nested_value in value.items():
            if _is_sensitive_metadata_key(key):
                raise AuditRepositoryValidationError(
                    "Sensitive audit metadata key is not allowed: "
                    f"{path}.{key}"
                )

            _validate_safe_metadata(
                nested_value,
                path=f"{path}.{key}",
                depth=depth + 1,
            )

        return

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
            frozenset,
        ),
    ):
        for index, nested_value in enumerate(value):
            _validate_safe_metadata(
                nested_value,
                path=f"{path}[{index}]",
                depth=depth + 1,
            )


# =============================================================================
# Generic Validation Helpers
# =============================================================================


def _validate_uuid(
    value: UUID,
    *,
    field_name: str,
) -> UUID:
    if not isinstance(value, UUID):
        raise AuditRepositoryValidationError(
            f"{field_name} must be a UUID."
        )

    return value


def _validate_optional_uuid(
    value: UUID | None,
    *,
    field_name: str,
) -> UUID | None:
    if value is None:
        return None

    return _validate_uuid(
        value,
        field_name=field_name,
    )


def _normalize_text(
    value: str | None,
    *,
    field_name: str,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise AuditRepositoryValidationError(
            f"{field_name} must be a string."
        )

    normalized = value.strip()

    return normalized or None


def _normalize_request_id(
    request_id: str | None,
) -> str | None:
    normalized = _normalize_text(
        request_id,
        field_name="request_id",
    )

    if normalized is None:
        return None

    if len(normalized) > MAX_REQUEST_ID_LENGTH:
        raise AuditRepositoryValidationError(
            "request_id must not exceed "
            f"{MAX_REQUEST_ID_LENGTH} characters."
        )

    return normalized


def _normalize_source_ip(
    source_ip: str | None,
) -> str | None:
    normalized = _normalize_text(
        source_ip,
        field_name="source_ip",
    )

    if normalized is None:
        return None

    if len(normalized) > MAX_SOURCE_IP_LENGTH:
        raise AuditRepositoryValidationError(
            "source_ip must not exceed "
            f"{MAX_SOURCE_IP_LENGTH} characters."
        )

    return normalized


def _normalize_datetime(
    value: datetime | None,
    *,
    field_name: str,
) -> datetime | None:
    if value is None:
        return None

    if not isinstance(value, datetime):
        raise AuditRepositoryValidationError(
            f"{field_name} must be a datetime."
        )

    if (
        value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise AuditRepositoryValidationError(
            f"{field_name} must be timezone-aware."
        )

    return value.astimezone(UTC)


def _normalize_datetime_range(
    *,
    date_from: datetime | None,
    date_to: datetime | None,
) -> tuple[datetime | None, datetime | None]:
    normalized_from = _normalize_datetime(
        date_from,
        field_name="date_from",
    )

    normalized_to = _normalize_datetime(
        date_to,
        field_name="date_to",
    )

    if (
        normalized_from is not None
        and normalized_to is not None
        and normalized_from > normalized_to
    ):
        raise AuditRepositoryValidationError(
            "date_from must not be later than date_to."
        )

    return (
        normalized_from,
        normalized_to,
    )


def _validate_page(
    page: int,
    page_size: int,
) -> None:
    if (
        isinstance(page, bool)
        or not isinstance(page, int)
    ):
        raise AuditRepositoryValidationError(
            "page must be an integer."
        )

    if (
        isinstance(page_size, bool)
        or not isinstance(page_size, int)
    ):
        raise AuditRepositoryValidationError(
            "page_size must be an integer."
        )

    if page < 1:
        raise AuditRepositoryValidationError(
            "page must be greater than or equal to 1."
        )

    if not 1 <= page_size <= MAX_PAGE_SIZE:
        raise AuditRepositoryValidationError(
            "page_size must be between 1 and "
            f"{MAX_PAGE_SIZE}."
        )


def _validate_limit(
    limit: int,
    *,
    maximum: int,
    field_name: str = "limit",
) -> None:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
    ):
        raise AuditRepositoryValidationError(
            f"{field_name} must be an integer."
        )

    if not 1 <= limit <= maximum:
        raise AuditRepositoryValidationError(
            f"{field_name} must be between 1 and "
            f"{maximum}."
        )


def _normalize_outcome(
    outcome: str | None,
) -> str:
    if outcome is None:
        raise AuditRepositoryValidationError(
            "outcome must not be empty."
        )

    if not isinstance(outcome, str):
        raise AuditRepositoryValidationError(
            "outcome must be a string."
        )

    normalized = outcome.strip().lower()

    if not normalized:
        raise AuditRepositoryValidationError(
            "outcome must not be empty."
        )

    if normalized not in CANONICAL_OUTCOMES:
        raise AuditRepositoryValidationError(
            "outcome must be one of: "
            "success, failure, denied."
        )

    return normalized


# =============================================================================
# Audit Record Validation
# =============================================================================


def validate_audit_record(
    event: AuditEvent,
) -> None:
    if not isinstance(event, AuditEvent):
        raise AuditRepositoryValidationError(
            "event must be an AuditEvent instance."
        )

    _validate_uuid(
        event.audit_id,
        field_name="audit_id",
    )

    _validate_optional_uuid(
        event.actor_user_id,
        field_name="actor_user_id",
    )

    _validate_optional_uuid(
        event.target_user_id,
        field_name="target_user_id",
    )

    _validate_optional_uuid(
        event.session_id,
        field_name="session_id",
    )

    action = _normalize_text(
        event.action,
        field_name="action",
    )

    if action is None:
        raise AuditRepositoryValidationError(
            "action must not be empty."
        )

    _normalize_outcome(event.outcome)

    _normalize_request_id(event.request_id)

    _normalize_source_ip(event.source_ip)

    _normalize_datetime(
        event.created_at,
        field_name="created_at",
    )

    if event.metadata_json is not None:
        if not isinstance(event.metadata_json, dict):
            raise AuditRepositoryValidationError(
                "metadata_json must be a dictionary or None."
            )

        _validate_safe_metadata(
            event.metadata_json,
        )


# =============================================================================
# Query Filter Builder
# =============================================================================


def _apply_filters(
    query: Any,
    *,
    actor_user_id: UUID | None = None,
    target_user_id: UUID | None = None,
    action: str | None = None,
    category: str | None = None,
    outcome: str | None = None,
    source_ip: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    search: str | None = None,
    session_id: UUID | None = None,
    request_id: str | None = None,
) -> Any:
    actor_user_id = _validate_optional_uuid(
        actor_user_id,
        field_name="actor_user_id",
    )

    target_user_id = _validate_optional_uuid(
        target_user_id,
        field_name="target_user_id",
    )

    session_id = _validate_optional_uuid(
        session_id,
        field_name="session_id",
    )

    action = _normalize_text(
        action,
        field_name="action",
    )

    category = _normalize_text(
        category,
        field_name="category",
    )

    normalized_outcome: str | None = None

    if outcome is not None:
        normalized_outcome = _normalize_outcome(
            outcome,
        )

    source_ip = _normalize_source_ip(source_ip)

    request_id = _normalize_request_id(request_id)

    search = _normalize_text(
        search,
        field_name="search",
    )

    date_from, date_to = _normalize_datetime_range(
        date_from=date_from,
        date_to=date_to,
    )

    if actor_user_id is not None:
        query = query.where(
            AuditEvent.actor_user_id == actor_user_id
        )

    if target_user_id is not None:
        query = query.where(
            AuditEvent.target_user_id == target_user_id
        )

    if action is not None:
        query = query.where(
            AuditEvent.action == action
        )

    if category is not None:
        category = category.rstrip(".")

        if category:
            query = query.where(
                AuditEvent.action.ilike(
                    f"{category}.%"
                )
            )

    if normalized_outcome is not None:
        query = query.where(
            func.lower(AuditEvent.outcome)
            == normalized_outcome
        )

    if source_ip is not None:
        query = query.where(
            cast(
                AuditEvent.source_ip,
                String,
            ).ilike(
                f"%{source_ip}%"
            )
        )

    if date_from is not None:
        query = query.where(
            AuditEvent.created_at >= date_from
        )

    if date_to is not None:
        query = query.where(
            AuditEvent.created_at <= date_to
        )

    if session_id is not None:
        query = query.where(
            AuditEvent.session_id == session_id
        )

    if request_id is not None:
        query = query.where(
            AuditEvent.request_id == request_id
        )

    if search is not None:
        pattern = f"%{search}%"

        query = query.where(
            or_(
                AuditEvent.action.ilike(pattern),
                AuditEvent.outcome.ilike(pattern),
                AuditEvent.request_id.ilike(pattern),
                cast(
                    AuditEvent.source_ip,
                    String,
                ).ilike(pattern),
                cast(
                    AuditEvent.metadata_json,
                    String,
                ).ilike(pattern),
            )
        )

    return query


# =============================================================================
# Audit Repository
# =============================================================================


class AuditRepository:
    """
    Canonical SQLAlchemy repository for SentinelSIEM audit events.
    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        if not isinstance(session, AsyncSession):
            raise AuditRepositoryValidationError(
                "session must be an AsyncSession."
            )

        self.session = session

    # =========================================================================
    # CREATE
    # =========================================================================

    async def create(
        self,
        audit: AuditCreate,
    ) -> AuditEvent:
        if not isinstance(audit, AuditCreate):
            raise AuditRepositoryValidationError(
                "audit must be an AuditCreate instance."
            )

        audit_id = _validate_uuid(
            audit.audit_id,
            field_name="audit_id",
        )

        actor_user_id = _validate_optional_uuid(
            audit.actor_user_id,
            field_name="actor_user_id",
        )

        target_user_id = _validate_optional_uuid(
            audit.target_user_id,
            field_name="target_user_id",
        )

        session_id = _validate_optional_uuid(
            audit.session_id,
            field_name="session_id",
        )

        action = _normalize_text(
            audit.action,
            field_name="action",
        )

        if action is None:
            raise AuditRepositoryValidationError(
                "action must not be empty."
            )

        outcome = _normalize_outcome(
            audit.outcome,
        )

        request_id = _normalize_request_id(
            audit.request_id,
        )

        source_ip = _normalize_source_ip(
            audit.source_ip,
        )

        created_at = _normalize_datetime(
            audit.created_at,
            field_name="created_at",
        )

        if created_at is None:
            raise AuditRepositoryValidationError(
                "created_at must not be None."
            )

        metadata_json = audit.metadata_json

        if metadata_json is not None:
            if not isinstance(metadata_json, dict):
                raise AuditRepositoryValidationError(
                    "metadata_json must be a dictionary or None."
                )

            _validate_safe_metadata(
                metadata_json,
            )

            metadata_json = dict(metadata_json)

        event = AuditEvent(
            audit_id=audit_id,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            session_id=session_id,
            request_id=request_id,
            source_ip=source_ip,
            action=action,
            outcome=outcome,
            metadata_json=metadata_json,
            created_at=created_at,
        )

        validate_audit_record(event)

        self.session.add(event)

        try:
            await self.session.flush()

        except IntegrityError as exc:
            raise AuditRepositoryError(
                "Unable to persist audit event because "
                "a database constraint was violated."
            ) from exc

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to persist audit event."
            ) from exc

        return event

    # =========================================================================
    # SINGLE EVENT
    # =========================================================================

    async def get_event(
        self,
        audit_id: UUID,
    ) -> AuditEvent | None:
        audit_id = _validate_uuid(
            audit_id,
            field_name="audit_id",
        )

        query = (
            select(AuditEvent)
            .where(
                AuditEvent.audit_id == audit_id
            )
        )

        try:
            result = await self.session.execute(query)

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to retrieve audit event."
            ) from exc

        return result.scalar_one_or_none()

    async def get_by_id(
        self,
        audit_id: UUID,
    ) -> AuditEvent | None:
        return await self.get_event(audit_id)

    # =========================================================================
    # GLOBAL LIST
    # =========================================================================

    async def list_events(
        self,
        *,
        page: int = DEFAULT_PAGE,
        page_size: int = DEFAULT_PAGE_SIZE,
        actor_user_id: UUID | None = None,
        target_user_id: UUID | None = None,
        action: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        source_ip: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
    ) -> tuple[list[AuditEvent], int]:

        _validate_page(page, page_size)

        events_query = _apply_filters(
            select(AuditEvent),
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        )

        count_query = _apply_filters(
            select(
                func.count(AuditEvent.audit_id)
            ),
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        )

        offset = (page - 1) * page_size

        events_query = (
            events_query
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.audit_id.desc(),
            )
            .offset(offset)
            .limit(page_size)
        )

        try:
            result = await self.session.execute(
                events_query
            )

            count_result = await self.session.execute(
                count_query
            )

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to retrieve global audit events."
            ) from exc

        events = list(result.scalars().all())

        total = int(
            count_result.scalar_one()
        )

        return events, total

    # =========================================================================
    # INDIVIDUAL AUDIT - SHARED FILTER BUILDER
    # =========================================================================

    def _build_user_audit_filters(
        self,
        user_id: UUID,
        *,
        action: str | None = None,
        outcome: str | None = None,
        target_user_id: UUID | None = None,
        source_ip: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        """
        Build the canonical Individual Audit filter contract.

        Scope:

            actor_user_id = selected user
            OR
            target_user_id = selected user

        Then apply:

            action
            outcome
            target_user_id
            source_ip
            date_from
            date_to
        """

        user_id = _validate_uuid(
            user_id,
            field_name="user_id",
        )

        target_user_id = _validate_optional_uuid(
            target_user_id,
            field_name="target_user_id",
        )

        action = _normalize_text(
            action,
            field_name="action",
        )

        normalized_outcome: str | None = None

        if outcome is not None:
            normalized_outcome = _normalize_outcome(
                outcome
            )

        source_ip = _normalize_source_ip(
            source_ip
        )

        date_from, date_to = _normalize_datetime_range(
            date_from=date_from,
            date_to=date_to,
        )

        user_scope = or_(
            AuditEvent.actor_user_id == user_id,
            AuditEvent.target_user_id == user_id,
        )

        filters: dict[str, Any] = {
            "user_scope": user_scope,
            "action": action,
            "outcome": normalized_outcome,
            "target_user_id": target_user_id,
            "source_ip": source_ip,
            "date_from": date_from,
            "date_to": date_to,
        }

        return user_scope, filters

    def _apply_user_audit_filters(
        self,
        query: Any,
        *,
        user_scope: Any,
        filters: dict[str, Any],
    ) -> Any:
        """
        Apply the canonical Individual Audit filters to any query.

        This is intentionally shared by:

            get_user_events()
            get_user_statistics()

        so the table, pagination total and statistics can never
        accidentally use different filtering rules.
        """

        query = query.where(user_scope)

        action = filters["action"]
        outcome = filters["outcome"]
        target_user_id = filters["target_user_id"]
        source_ip = filters["source_ip"]
        date_from = filters["date_from"]
        date_to = filters["date_to"]

        if action is not None:
            query = query.where(
                AuditEvent.action == action
            )

        if outcome is not None:
            query = query.where(
                func.lower(AuditEvent.outcome)
                == outcome
            )

        if target_user_id is not None:
            query = query.where(
                AuditEvent.target_user_id
                == target_user_id
            )

        if source_ip is not None:
            query = query.where(
                cast(
                    AuditEvent.source_ip,
                    String,
                ).ilike(
                    f"%{source_ip}%"
                )
            )

        if date_from is not None:
            query = query.where(
                AuditEvent.created_at >= date_from
            )

        if date_to is not None:
            query = query.where(
                AuditEvent.created_at <= date_to
            )

        return query

    # =========================================================================
    # USER AUDIT HISTORY
    # =========================================================================

    async def get_user_events(
        self,
        user_id: UUID,
        *,
        page: int = DEFAULT_PAGE,
        page_size: int = DEFAULT_PAGE_SIZE,
        action: str | None = None,
        outcome: str | None = None,
        target_user_id: UUID | None = None,
        source_ip: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> tuple[list[AuditEvent], int]:
        """
        Retrieve paginated Individual User Audit history.

        Individual Audit contract:

            selected user
                ↓
            actor_user_id = selected user
            OR
            target_user_id = selected user

            AND optional filters:
                action
                outcome
                target_user_id
                source_ip
                date_from
                date_to

        Actor is intentionally NOT an exposed filter.
        """

        _validate_page(
            page,
            page_size,
        )

        user_scope, filters = self._build_user_audit_filters(
            user_id,
            action=action,
            outcome=outcome,
            target_user_id=target_user_id,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
        )

        events_query = self._apply_user_audit_filters(
            select(AuditEvent),
            user_scope=user_scope,
            filters=filters,
        )

        count_query = self._apply_user_audit_filters(
            select(
                func.count(AuditEvent.audit_id)
            ),
            user_scope=user_scope,
            filters=filters,
        )

        offset = (page - 1) * page_size

        events_query = (
            events_query
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.audit_id.desc(),
            )
            .offset(offset)
            .limit(page_size)
        )

        try:
            result = await self.session.execute(
                events_query
            )

            count_result = await self.session.execute(
                count_query
            )

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to retrieve user audit history."
            ) from exc

        events = list(
            result.scalars().all()
        )

        total = int(
            count_result.scalar_one()
        )

        return events, total

    # =========================================================================
    # INDIVIDUAL AUDIT STATISTICS
    # =========================================================================

    async def get_user_statistics(
        self,
        user_id: UUID,
        *,
        action: str | None = None,
        outcome: str | None = None,
        target_user_id: UUID | None = None,
        source_ip: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> dict[str, int]:
        """
        Calculate statistics for the complete filtered Individual
        User Audit dataset.

        IMPORTANT:

        This does NOT count only the currently paginated 30 events.

        It calculates statistics over ALL events matching the same
        Individual Audit filters.

        Returns:

            {
                "total": ...,
                "success": ...,
                "failure": ...,
                "denied": ...,
            }

        Example:

            143 matching events

            success = 30
            failure = 113
            denied = 0

        Result:

            {
                "total": 143,
                "success": 30,
                "failure": 113,
                "denied": 0,
            }
        """

        user_scope, filters = self._build_user_audit_filters(
            user_id,
            action=action,
            outcome=outcome,
            target_user_id=target_user_id,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
        )

        # ---------------------------------------------------------------------
        # One aggregate query for the complete filtered dataset.
        #
        # CASE expressions count each canonical outcome independently.
        #
        # Because the same filters are applied to the query itself:
        #
        #   outcome=None
        #       -> total dataset statistics
        #
        #   outcome="failure"
        #       -> only failure events
        #
        #   action="users.disabled"
        #       -> only matching action events
        #
        #   target_user_id=B
        #       -> only events targeting B
        # ---------------------------------------------------------------------

        statistics_query = select(
            func.count(
                AuditEvent.audit_id
            ).label("total"),

            func.coalesce(
                func.sum(
                    case(
                        (
                            func.lower(
                                AuditEvent.outcome
                            )
                            == "success",
                            1,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("success"),

            func.coalesce(
                func.sum(
                    case(
                        (
                            func.lower(
                                AuditEvent.outcome
                            )
                            == "failure",
                            1,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("failure"),

            func.coalesce(
                func.sum(
                    case(
                        (
                            func.lower(
                                AuditEvent.outcome
                            )
                            == "denied",
                            1,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("denied"),
        )

        statistics_query = self._apply_user_audit_filters(
            statistics_query,
            user_scope=user_scope,
            filters=filters,
        )

        try:
            result = await self.session.execute(
                statistics_query
            )

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to calculate individual user "
                "audit statistics."
            ) from exc

        row = result.one()

        return {
            "total": int(
                row.total or 0
            ),
            "success": int(
                row.success or 0
            ),
            "failure": int(
                row.failure or 0
            ),
            "denied": int(
                row.denied or 0
            ),
        }

    # =========================================================================
    # RECENT USER ACTIVITY
    # =========================================================================

    async def get_user_activity(
        self,
        user_id: UUID,
        *,
        limit: int = DEFAULT_USER_EVENTS_LIMIT,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
    ) -> list[AuditEvent]:

        user_id = _validate_uuid(
            user_id,
            field_name="user_id",
        )

        _validate_limit(
            limit,
            maximum=MAX_USER_EVENTS_LIMIT,
        )

        user_condition = or_(
            AuditEvent.actor_user_id == user_id,
            AuditEvent.target_user_id == user_id,
        )

        query = _apply_filters(
            select(AuditEvent),
            date_from=date_from,
            date_to=date_to,
            session_id=session_id,
            request_id=request_id,
        ).where(
            user_condition
        )

        query = (
            query
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.audit_id.desc(),
            )
            .limit(limit)
        )

        try:
            result = await self.session.execute(
                query
            )

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to retrieve recent user activity."
            ) from exc

        return list(
            result.scalars().all()
        )

    # =========================================================================
    # LEGACY PAGINATED USER ACTIVITY
    # =========================================================================

    async def list_user_activity(
        self,
        user_id: UUID,
        *,
        page: int = DEFAULT_PAGE,
        page_size: int = DEFAULT_PAGE_SIZE,
        action: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        result: str | None = None,
        source_ip: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
    ) -> tuple[list[AuditEvent], int]:

        if (
            outcome is not None
            and result is not None
        ):
            raise AuditRepositoryValidationError(
                "Provide either outcome or result, not both."
            )

        effective_outcome = (
            outcome
            if outcome is not None
            else result
        )

        return await self._get_user_events_legacy(
            user_id=user_id,
            page=page,
            page_size=page_size,
            action=action,
            category=category,
            outcome=effective_outcome,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        )

    async def _get_user_events_legacy(
        self,
        user_id: UUID,
        *,
        page: int,
        page_size: int,
        action: str | None,
        category: str | None,
        outcome: str | None,
        source_ip: str | None,
        date_from: datetime | None,
        date_to: datetime | None,
        search: str | None,
        session_id: UUID | None,
        request_id: str | None,
    ) -> tuple[list[AuditEvent], int]:

        user_id = _validate_uuid(
            user_id,
            field_name="user_id",
        )

        _validate_page(
            page,
            page_size,
        )

        user_condition = or_(
            AuditEvent.actor_user_id == user_id,
            AuditEvent.target_user_id == user_id,
        )

        events_query = _apply_filters(
            select(AuditEvent),
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        ).where(
            user_condition
        )

        count_query = _apply_filters(
            select(
                func.count(AuditEvent.audit_id)
            ),
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        ).where(
            user_condition
        )

        offset = (page - 1) * page_size

        events_query = (
            events_query
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.audit_id.desc(),
            )
            .offset(offset)
            .limit(page_size)
        )

        try:
            result = await self.session.execute(
                events_query
            )

            count_result = await self.session.execute(
                count_query
            )

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to retrieve user activity."
            ) from exc

        events = list(
            result.scalars().all()
        )

        total = int(
            count_result.scalar_one()
        )

        return events, total

    # =========================================================================
    # RELATED EVENTS
    # =========================================================================

    async def get_related_events(
        self,
        audit_id: UUID,
        *,
        limit: int = DEFAULT_RELATED_LIMIT,
    ) -> list[AuditEvent]:

        audit_id = _validate_uuid(
            audit_id,
            field_name="audit_id",
        )

        _validate_limit(
            limit,
            maximum=MAX_RELATED_LIMIT,
        )

        parent = await self.get_event(audit_id)

        if parent is None:
            return []

        conditions: list[Any] = []

        if parent.session_id is not None:
            conditions.append(
                AuditEvent.session_id == parent.session_id
            )

        if parent.request_id is not None:
            conditions.append(
                AuditEvent.request_id == parent.request_id
            )

        if parent.actor_user_id is not None:
            conditions.append(
                AuditEvent.actor_user_id
                == parent.actor_user_id
            )

        if parent.target_user_id is not None:
            conditions.append(
                AuditEvent.target_user_id
                == parent.target_user_id
            )

        if not conditions:
            return []

        query = (
            select(AuditEvent)
            .where(
                AuditEvent.audit_id != audit_id
            )
            .where(
                or_(*conditions)
            )
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.audit_id.desc(),
            )
            .limit(limit)
        )

        try:
            result = await self.session.execute(query)

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to retrieve related audit events."
            ) from exc

        return list(
            result.scalars().all()
        )

    # =========================================================================
    # SESSION CORRELATION
    # =========================================================================

    async def list_by_session(
        self,
        session_id: UUID,
        *,
        limit: int = DEFAULT_RELATED_LIMIT,
    ) -> list[AuditEvent]:

        session_id = _validate_uuid(
            session_id,
            field_name="session_id",
        )

        _validate_limit(
            limit,
            maximum=MAX_RELATED_LIMIT,
        )

        query = (
            select(AuditEvent)
            .where(
                AuditEvent.session_id == session_id
            )
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.audit_id.desc(),
            )
            .limit(limit)
        )

        try:
            result = await self.session.execute(query)

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to retrieve session audit events."
            ) from exc

        return list(
            result.scalars().all()
        )

    # =========================================================================
    # REQUEST CORRELATION
    # =========================================================================

    async def list_by_request(
        self,
        request_id: str,
        *,
        limit: int = DEFAULT_RELATED_LIMIT,
    ) -> list[AuditEvent]:

        request_id = _normalize_request_id(request_id)

        if request_id is None:
            raise AuditRepositoryValidationError(
                "request_id must not be empty."
            )

        _validate_limit(
            limit,
            maximum=MAX_RELATED_LIMIT,
        )

        query = (
            select(AuditEvent)
            .where(
                AuditEvent.request_id == request_id
            )
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.audit_id.desc(),
            )
            .limit(limit)
        )

        try:
            result = await self.session.execute(query)

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to retrieve request audit events."
            ) from exc

        return list(
            result.scalars().all()
        )

    # =========================================================================
    # COUNT
    # =========================================================================

    async def count_events(
        self,
        *,
        actor_user_id: UUID | None = None,
        target_user_id: UUID | None = None,
        action: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        source_ip: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
    ) -> int:

        query = _apply_filters(
            select(
                func.count(AuditEvent.audit_id)
            ),
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        )

        try:
            result = await self.session.execute(query)

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to count audit events."
            ) from exc

        return int(
            result.scalar_one()
        )

    # =========================================================================
    # GLOBAL STATISTICS
    # =========================================================================

    async def get_statistics(
        self,
        *,
        actor_user_id: UUID | None = None,
        target_user_id: UUID | None = None,
        action: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        source_ip: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
    ) -> dict[str, int]:

        common_filters = {
            "actor_user_id": actor_user_id,
            "target_user_id": target_user_id,
            "action": action,
            "category": category,
            "source_ip": source_ip,
            "date_from": date_from,
            "date_to": date_to,
            "search": search,
            "session_id": session_id,
            "request_id": request_id,
        }

        total_query = _apply_filters(
            select(
                func.count(AuditEvent.audit_id)
            ),
            **common_filters,
        )

        success_query = _apply_filters(
            select(
                func.count(AuditEvent.audit_id)
            ),
            outcome="success",
            **common_filters,
        )

        failure_query = _apply_filters(
            select(
                func.count(AuditEvent.audit_id)
            ),
            outcome="failure",
            **common_filters,
        )

        denied_query = _apply_filters(
            select(
                func.count(AuditEvent.audit_id)
            ),
            outcome="denied",
            **common_filters,
        )

        unique_actors_query = _apply_filters(
            select(
                func.count(
                    func.distinct(
                        AuditEvent.actor_user_id
                    )
                )
            ),
            **common_filters,
        )

        unique_targets_query = _apply_filters(
            select(
                func.count(
                    func.distinct(
                        AuditEvent.target_user_id
                    )
                )
            ),
            **common_filters,
        )

        try:
            total_result = await self.session.execute(
                total_query
            )

            success_result = await self.session.execute(
                success_query
            )

            failure_result = await self.session.execute(
                failure_query
            )

            denied_result = await self.session.execute(
                denied_query
            )

            unique_actors_result = await self.session.execute(
                unique_actors_query
            )

            unique_targets_result = await self.session.execute(
                unique_targets_query
            )

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to calculate audit statistics."
            ) from exc

        return {
            "total": int(
                total_result.scalar_one()
            ),
            "success": int(
                success_result.scalar_one()
            ),
            "failure": int(
                failure_result.scalar_one()
            ),
            "denied": int(
                denied_result.scalar_one()
            ),
            "unique_actors": int(
                unique_actors_result.scalar_one()
            ),
            "unique_targets": int(
                unique_targets_result.scalar_one()
            ),
        }

    async def statistics(
        self,
        **kwargs: Any,
    ) -> dict[str, int]:
        return await self.get_statistics(
            **kwargs
        )

    # =========================================================================
    # EXPORT
    # =========================================================================

    async def get_export_events(
        self,
        *,
        actor_user_id: UUID | None = None,
        target_user_id: UUID | None = None,
        action: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        source_ip: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
        limit: int = DEFAULT_EXPORT_LIMIT,
    ) -> list[AuditEvent]:

        _validate_limit(
            limit,
            maximum=MAX_EXPORT_LIMIT,
        )

        query = _apply_filters(
            select(AuditEvent),
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        )

        query = (
            query
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.audit_id.desc(),
            )
            .limit(limit)
        )

        try:
            result = await self.session.execute(query)

        except SQLAlchemyError as exc:
            raise AuditRepositoryError(
                "Unable to retrieve audit export dataset."
            ) from exc

        return list(
            result.scalars().all()
        )

    async def export_events(
        self,
        **kwargs: Any,
    ) -> list[AuditEvent]:
        return await self.get_export_events(
            **kwargs
        )

    # =========================================================================
    # LEGACY COMPATIBILITY
    # =========================================================================

    async def list_logs(
        self,
        *,
        page: int = DEFAULT_PAGE,
        page_size: int = DEFAULT_PAGE_SIZE,
        actor: UUID | None = None,
        target: UUID | None = None,
        action: str | None = None,
        category: str | None = None,
        result: str | None = None,
        source: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
    ) -> tuple[list[AuditEvent], int]:

        return await self.list_events(
            page=page,
            page_size=page_size,
            actor_user_id=actor,
            target_user_id=target,
            action=action,
            category=category,
            outcome=result,
            source_ip=source,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        )

    async def count_logs(
        self,
        *,
        actor: UUID | None = None,
        target: UUID | None = None,
        action: str | None = None,
        category: str | None = None,
        result: str | None = None,
        source: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
    ) -> int:

        return await self.count_events(
            actor_user_id=actor,
            target_user_id=target,
            action=action,
            category=category,
            outcome=result,
            source_ip=source,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        )


# =============================================================================
# In-Memory Audit Sink
# =============================================================================


class InMemoryAuditSink:
    """
    Deterministic in-memory audit sink for unit tests.
    """

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(
        self,
        event: AuditEvent,
    ) -> None:
        validate_audit_record(event)

        self._events.append(event)

    def all(
        self,
    ) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def latest(
        self,
    ) -> AuditEvent | None:
        if not self._events:
            return None

        return self._events[-1]

    def count(
        self,
    ) -> int:
        return len(self._events)

    def clear(
        self,
    ) -> None:
        self._events.clear()


# =============================================================================
# Public Exports
# =============================================================================


__all__ = [
    "AuditRepository",
    "AuditRepositoryError",
    "AuditRepositoryValidationError",
    "AuditValidationError",
    "InMemoryAuditSink",
    "validate_audit_record",
    "DEFAULT_PAGE",
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "DEFAULT_USER_EVENTS_LIMIT",
    "MAX_USER_EVENTS_LIMIT",
    "DEFAULT_RELATED_LIMIT",
    "MAX_RELATED_LIMIT",
    "DEFAULT_EXPORT_LIMIT",
    "MAX_EXPORT_LIMIT",
    "MAX_REQUEST_ID_LENGTH",
    "MAX_SOURCE_IP_LENGTH",
    "MAX_METADATA_DEPTH",
    "CANONICAL_OUTCOMES",
]