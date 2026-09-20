"""
SentinelSIEM — Canonical Global Audit Service
=============================================

Application/service layer for the centralized SentinelSIEM audit subsystem.

Architecture
------------

    API
      |
      v
    AuditService
      |
      +----------------------+
      |                      |
      v                      v
    AuditRepository      UserRepository
      |                      |
      v                      v
    siem_auth_audit      UserIdentity
      |
      v
    Enriched Audit Event
      |
      v
    API Response


Responsibilities
----------------

The service owns:

    - application-level validation
    - sensitive metadata protection
    - audit creation
    - audit retrieval
    - user identity enrichment
    - actor/target mapping
    - category derivation
    - source/user-agent extraction from safe metadata
    - global audit queries
    - user audit history
    - individual user audit statistics
    - related-event retrieval
    - session correlation
    - request correlation
    - statistics
    - counting
    - export preparation

The service does NOT own:

    - HTTP/FastAPI
    - authentication decisions
    - RBAC decisions
    - raw SQL/query construction
    - database transaction commit
    - database transaction rollback
    - database session closing
    - audit update
    - audit deletion


Individual User Audit
---------------------

The Individual User Audit API supports:

    action
    outcome
    target_user_id
    source_ip
    date_from
    date_to
    page
    page_size

The selected user remains the base audit subject:

    actor_user_id = user_id
    OR
    target_user_id = user_id

The service does not expose an actor filter for Individual Audit.

Category/search filters remain available to Global Audit APIs
but are intentionally not part of get_user_events().

Individual Audit statistics use the exact same filter contract
as Individual Audit event retrieval.

Identity Contract
-----------------

Canonical persisted references:

    actor_user_id
    target_user_id

Resolved API identities:

    actor
    target

Resolved identity:

    user_id
    username
    role

Semantics:

    actor_user_id is None
        -> actor remains None
        -> presentation layer may render System

    target_user_id is None
        -> target MUST remain None
        -> presentation layer may render No Target

The service NEVER invents:

    target = "User"
    target = "Unknown User"


Transaction Contract
--------------------

The service NEVER performs:

    session.commit()
    session.rollback()
    session.close()

The caller/application layer owns transaction lifecycle.


Security
--------

Audit metadata is untrusted input.

Credential-bearing metadata is rejected recursively.

The service never exposes:

    - password
    - password_hash
    - access_token
    - refresh_token
    - session_token
    - JWT
    - API key
    - client secret
    - private key
    - authorization header
    - cookies
    - credential material
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Any, Iterable
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.repository import (
    AuditRepository,
    AuditRepositoryError,
    AuditRepositoryValidationError,
)
from app.audit.schemas import (
    AuditCreate,
    CANONICAL_OUTCOMES,
)
from app.auth.adapters import PostgresUserRepository
from app.auth.models import UserIdentity


# =============================================================================
# Constants
# =============================================================================

MAX_ACTION_LENGTH = 150
MAX_OUTCOME_LENGTH = 50
MAX_CATEGORY_LENGTH = 100
MAX_SEARCH_LENGTH = 500

MAX_REQUEST_ID_LENGTH = 100
MAX_SOURCE_IP_LENGTH = 45

MAX_USERNAME_LENGTH = 255
MAX_USER_AGENT_LENGTH = 1000

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

DEFAULT_RELATED_LIMIT = 100
MAX_RELATED_LIMIT = 200

DEFAULT_RECENT_LIMIT = 50
MAX_RECENT_LIMIT = 200

DEFAULT_EXPORT_LIMIT = 10_000
MAX_EXPORT_LIMIT = 50_000

MAX_METADATA_DEPTH = 10


# =============================================================================
# Exceptions
# =============================================================================


class AuditServiceError(RuntimeError):
    """
    Base exception for all audit service failures.
    """


class AuditValidationError(AuditServiceError):
    """
    Raised when audit service input violates application-level rules.
    """


# =============================================================================
# Service
# =============================================================================


class AuditService:
    """
    Canonical application service for SentinelSIEM Global Audit.

    The service coordinates:

        AuditRepository
            +
        UserRepository
            |
            v
        Enriched Audit Event

    The repository remains responsible for persistence/query construction.

    The service remains responsible for application mapping and
    presentation-safe identity enrichment.
    """

    # =========================================================================
    # Sensitive metadata protection
    # =========================================================================

    _FORBIDDEN_METADATA_KEYS: frozenset[str] = frozenset(
        {
            # -----------------------------------------------------------------
            # Passwords
            # -----------------------------------------------------------------
            "password",
            "passwd",
            "pass",
            "pwd",
            "passphrase",
            "password_hash",
            "passwordhash",
            "hashed_password",
            "hashedpassword",
            "hash_password",
            "hashpassword",
            "new_password",
            "newpassword",
            "current_password",
            "currentpassword",
            "old_password",
            "oldpassword",
            "plaintext_password",
            "plaintextpassword",
            "plain_password",
            "plainpassword",
            "password_value",
            "passwordvalue",

            # -----------------------------------------------------------------
            # Tokens
            # -----------------------------------------------------------------
            "token",
            "token_id",
            "tokenid",
            "token_value",
            "tokenvalue",
            "access_token",
            "accesstoken",
            "refresh_token",
            "refreshtoken",
            "id_token",
            "idtoken",
            "session_token",
            "sessiontoken",
            "bearer_token",
            "bearertoken",
            "jwt",
            "jwt_token",
            "jwttoken",
            "jwt_value",
            "jwtvalue",

            # -----------------------------------------------------------------
            # API / secrets
            # -----------------------------------------------------------------
            "api_key",
            "apikey",
            "api_key_value",
            "apikeyvalue",
            "client_secret",
            "clientsecret",
            "client_secret_value",
            "clientsecretvalue",
            "secret",
            "secret_key",
            "secretkey",
            "secret_value",
            "secretvalue",
            "private_key",
            "privatekey",
            "private_key_value",
            "privatekeyvalue",
            "encryption_key",
            "encryptionkey",
            "signing_key",
            "signingkey",

            # -----------------------------------------------------------------
            # Authorization / cookies
            # -----------------------------------------------------------------
            "authorization",
            "authorization_header",
            "authorizationheader",
            "auth_header",
            "authheader",
            "cookie",
            "cookies",
            "set_cookie",
            "setcookie",

            # -----------------------------------------------------------------
            # Credentials
            # -----------------------------------------------------------------
            "credential",
            "credentials",
            "credential_material",
            "credentialmaterial",
            "credential_value",
            "credentialvalue",
            "session_secret",
            "sessionsecret",
        }
    )

    _FORBIDDEN_METADATA_FRAGMENTS: tuple[str, ...] = (
        "password",
        "passwordhash",
        "hashedpassword",
        "plaintextpassword",
        "plainpassword",
        "passwordvalue",
        "accesstoken",
        "refreshtoken",
        "sessiontoken",
        "bearertoken",
        "jwttoken",
        "jwtvalue",
        "idtoken",
        "tokenvalue",
        "tokenid",
        "apikey",
        "apikeyvalue",
        "clientsecret",
        "clientsecretvalue",
        "secretvalue",
        "privatekey",
        "privatekeyvalue",
        "encryptionkey",
        "signingkey",
        "authorizationheader",
        "authheader",
        "credentialmaterial",
        "credentialvalue",
        "sessionsecret",
    )

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(
        self,
        session: AsyncSession,
        *,
        user_repository: Any | None = None,
    ) -> None:
        """
        Initialize the canonical AuditService.

        No new database session is created.
        """

        if not isinstance(
            session,
            AsyncSession,
        ):
            raise AuditValidationError(
                "session must be an AsyncSession."
            )

        self._session = session

        self._repository = AuditRepository(
            session,
        )

        self._users = (
            user_repository
            if user_repository is not None
            else PostgresUserRepository(
                session,
            )
        )

    @property
    def repository(self) -> AuditRepository:
        """
        Return the canonical audit repository.
        """

        return self._repository

    @property
    def user_repository(self) -> Any:
        """
        Return the user identity repository used for enrichment.
        """

        return self._users

    # =========================================================================
    # Metadata
    # =========================================================================

    @classmethod
    def _normalize_metadata_key(
        cls,
        key: object,
    ) -> str:
        """
        Normalize metadata keys for security comparison.
        """

        value = str(
            key,
        ).strip().lower()

        for separator in (
            "-",
            " ",
            ".",
            "/",
            "\\",
        ):
            value = value.replace(
                separator,
                "_",
            )

        while "__" in value:
            value = value.replace(
                "__",
                "_",
            )

        return value

    @classmethod
    def _is_forbidden_metadata_key(
        cls,
        key: object,
    ) -> bool:
        """
        Return True when a metadata key is credential-bearing.
        """

        normalized = cls._normalize_metadata_key(
            key,
        )

        if normalized in cls._FORBIDDEN_METADATA_KEYS:
            return True

        compact = normalized.replace(
            "_",
            "",
        )

        return any(
            fragment in compact
            for fragment in cls._FORBIDDEN_METADATA_FRAGMENTS
        )

    @classmethod
    def _walk_metadata(
        cls,
        value: Any,
        *,
        path: str,
        depth: int = 0,
    ) -> None:
        """
        Recursively validate audit metadata.
        """

        if depth > MAX_METADATA_DEPTH:
            raise AuditValidationError(
                "Audit metadata exceeds maximum nesting depth "
                f"of {MAX_METADATA_DEPTH}."
            )

        if isinstance(
            value,
            dict,
        ):
            for key, nested in value.items():

                if cls._is_forbidden_metadata_key(
                    key,
                ):
                    raise AuditValidationError(
                        "Sensitive credential material cannot be "
                        "stored in audit metadata: "
                        f"{path}.{key}"
                    )

                cls._walk_metadata(
                    nested,
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
            for index, nested in enumerate(
                value,
            ):
                cls._walk_metadata(
                    nested,
                    path=f"{path}[{index}]",
                    depth=depth + 1,
                )

    @classmethod
    def _prepare_metadata(
        cls,
        metadata: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """
        Validate and shallow-copy caller-owned metadata.
        """

        if metadata is None:
            return None

        if not isinstance(
            metadata,
            dict,
        ):
            raise AuditValidationError(
                "metadata_json must be a dictionary."
            )

        cls._walk_metadata(
            metadata,
            path="metadata_json",
        )

        return dict(
            metadata,
        )

    # =========================================================================
    # Generic metadata helpers
    # =========================================================================

    @staticmethod
    def _safe_metadata_dict(
        event: Any,
    ) -> dict[str, Any]:
        """
        Return a safe dictionary representation of event metadata.
        """

        metadata = getattr(
            event,
            "metadata_json",
            None,
        )

        if metadata is None:
            return {}

        if not isinstance(
            metadata,
            dict,
        ):
            try:
                return dict(
                    metadata,
                )
            except (
                TypeError,
                ValueError,
            ) as exc:
                raise AuditServiceError(
                    "Audit event metadata is not serializable."
                ) from exc

        return dict(
            metadata,
        )

    @classmethod
    def _safe_metadata_value(
        cls,
        metadata: dict[str, Any],
        *keys: str,
    ) -> Any:
        """
        Read the first explicitly requested metadata key.
        """

        normalized_metadata = {
            cls._normalize_metadata_key(
                key
            ): value
            for key, value in metadata.items()
        }

        for key in keys:
            normalized_key = cls._normalize_metadata_key(
                key,
            )

            if normalized_key in normalized_metadata:
                return normalized_metadata[
                    normalized_key
                ]

        return None

    @classmethod
    def _resolve_source(
        cls,
        event: Any,
    ) -> str | None:
        """
        Resolve an explicitly persisted source value.

        The service never invents a source value.
        """

        metadata = cls._safe_metadata_dict(
            event,
        )

        value = cls._safe_metadata_value(
            metadata,
            "source",
            "source_name",
            "source_type",
        )

        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            value = str(
                value,
            )

        value = value.strip()

        return value[:100] if value else None

    @classmethod
    def _resolve_user_agent(
        cls,
        event: Any,
    ) -> str | None:
        """
        Resolve user-agent information from safe persisted metadata.
        """

        metadata = cls._safe_metadata_dict(
            event,
        )

        value = cls._safe_metadata_value(
            metadata,
            "user_agent",
            "user-agent",
            "http_user_agent",
        )

        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            value = str(
                value,
            )

        value = value.strip()

        return (
            value[:MAX_USER_AGENT_LENGTH]
            if value
            else None
        )

    @staticmethod
    def _resolve_category(
        event: Any,
    ) -> str:
        """
        Resolve canonical audit category from the action namespace.

        Examples:

            users.list
                -> users

            authentication.login_success
                -> authentication
        """

        action = getattr(
            event,
            "action",
            None,
        )

        if not isinstance(
            action,
            str,
        ):
            return "unknown"

        normalized = action.strip()

        if not normalized:
            return "unknown"

        category = normalized.split(
            ".",
            1,
        )[0].strip()

        if not category:
            return "unknown"

        return category[:MAX_CATEGORY_LENGTH]

    # =========================================================================
    # Identity enrichment
    # =========================================================================

    @staticmethod
    def _normalize_roles(
        user: UserIdentity,
    ) -> str:
        """
        Convert UserIdentity roles into a deterministic display role.
        """

        roles = getattr(
            user,
            "roles",
            None,
        )

        if not roles:
            return "User"

        normalized_roles = sorted(
            {
                str(role).strip()
                for role in roles
                if str(role).strip()
            }
        )

        if not normalized_roles:
            return "User"

        return ", ".join(
            normalized_roles,
        )[:100]

    @classmethod
    def _build_identity_reference(
        cls,
        user: UserIdentity,
    ) -> dict[str, Any]:
        """
        Build the public-safe audit identity object.

        Only:

            user_id
            username
            role

        are exposed.
        """

        user_id = getattr(
            user,
            "user_id",
            None,
        )

        username = getattr(
            user,
            "username",
            None,
        )

        if not isinstance(
            user_id,
            UUID,
        ):
            raise AuditServiceError(
                "User identity has an invalid user_id."
            )

        if not isinstance(
            username,
            str,
        ):
            raise AuditServiceError(
                "User identity has an invalid username."
            )

        username = username.strip()

        if not username:
            raise AuditServiceError(
                "User identity has an empty username."
            )

        return {
            "user_id": user_id,
            "username": username[:MAX_USERNAME_LENGTH],
            "role": cls._normalize_roles(
                user,
            ),
        }

    async def _resolve_identity(
        self,
        user_id: UUID | None,
    ) -> dict[str, Any] | None:
        """
        Resolve one persisted user UUID.

        Missing or unknown users resolve to None.
        No fake identity is created.
        """

        if user_id is None:
            return None

        try:
            user = await self._users.get_by_id(
                user_id,
            )

        except Exception as exc:
            raise AuditServiceError(
                "Unable to resolve audit user identity."
            ) from exc

        if user is None:
            return None

        return self._build_identity_reference(
            user,
        )

    async def _enrich_event(
        self,
        event: Any,
    ) -> Any:
        """
        Enrich one canonical AuditEvent with safe presentation fields.

        Enriched attributes:

            actor
            target
            category
            source
            user_agent

        Persisted UUID references remain untouched.
        """

        if event is None:
            return None

        actor_user_id = getattr(
            event,
            "actor_user_id",
            None,
        )

        target_user_id = getattr(
            event,
            "target_user_id",
            None,
        )

        actor = await self._resolve_identity(
            actor_user_id,
        )

        target = await self._resolve_identity(
            target_user_id,
        )

        if target_user_id is None:
            target = None

        category = self._resolve_category(
            event,
        )

        source = self._resolve_source(
            event,
        )

        user_agent = self._resolve_user_agent(
            event,
        )

        try:
            event.actor = actor
            event.target = target
            event.category = category
            event.source = source
            event.user_agent = user_agent

            return event

        except Exception:
            return SimpleNamespace(
                audit_id=getattr(
                    event,
                    "audit_id",
                    None,
                ),
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                session_id=getattr(
                    event,
                    "session_id",
                    None,
                ),
                request_id=getattr(
                    event,
                    "request_id",
                    None,
                ),
                source_ip=getattr(
                    event,
                    "source_ip",
                    None,
                ),
                action=getattr(
                    event,
                    "action",
                    None,
                ),
                outcome=getattr(
                    event,
                    "outcome",
                    None,
                ),
                metadata_json=self._safe_metadata_dict(
                    event,
                ),
                created_at=getattr(
                    event,
                    "created_at",
                    None,
                ),
                actor=actor,
                target=target,
                category=category,
                source=source,
                user_agent=user_agent,
            )

    async def _enrich_events(
        self,
        events: Iterable[Any],
    ) -> list[Any]:
        """
        Enrich a collection of audit events.
        """

        enriched: list[Any] = []

        for event in events:
            enriched.append(
                await self._enrich_event(
                    event,
                )
            )

        return enriched

    # =========================================================================
    # Validation
    # =========================================================================

    @staticmethod
    def _validate_string(
        value: str,
        *,
        field_name: str,
    ) -> str:
        """
        Validate required string input.
        """

        if not isinstance(
            value,
            str,
        ):
            raise AuditValidationError(
                f"{field_name} must be a string."
            )

        value = value.strip()

        if not value:
            raise AuditValidationError(
                f"{field_name} must not be empty."
            )

        return value

    @staticmethod
    def _optional_string(
        value: str | None,
        *,
        field_name: str,
        maximum: int,
    ) -> str | None:
        """
        Validate optional string input.
        """

        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            raise AuditValidationError(
                f"{field_name} must be a string."
            )

        value = value.strip()

        if not value:
            return None

        if len(value) > maximum:
            raise AuditValidationError(
                f"{field_name} exceeds maximum length of {maximum}."
            )

        return value

    @staticmethod
    def _validate_uuid(
        value: UUID,
        *,
        field_name: str,
    ) -> UUID:
        """
        Validate required UUID input.
        """

        if not isinstance(
            value,
            UUID,
        ):
            raise AuditValidationError(
                f"{field_name} must be a UUID."
            )

        return value

    @staticmethod
    def _optional_uuid(
        value: UUID | None,
        *,
        field_name: str,
    ) -> UUID | None:
        """
        Validate optional UUID input.
        """

        if value is None:
            return None

        return AuditService._validate_uuid(
            value,
            field_name=field_name,
        )

    @staticmethod
    def _validate_page(
        page: int,
    ) -> None:
        """
        Validate one-based page number.
        """

        if (
            isinstance(page, bool)
            or not isinstance(page, int)
        ):
            raise AuditValidationError(
                "page must be an integer."
            )

        if page < 1:
            raise AuditValidationError(
                "page must be greater than or equal to 1."
            )

    @staticmethod
    def _validate_page_size(
        page_size: int,
    ) -> None:
        """
        Validate page size.
        """

        if (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
        ):
            raise AuditValidationError(
                "page_size must be an integer."
            )

        if not 1 <= page_size <= MAX_PAGE_SIZE:
            raise AuditValidationError(
                f"page_size must be between 1 and {MAX_PAGE_SIZE}."
            )

    @staticmethod
    def _validate_limit(
        limit: int,
        *,
        maximum: int,
        field_name: str = "limit",
    ) -> None:
        """
        Validate bounded positive limit.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
        ):
            raise AuditValidationError(
                f"{field_name} must be an integer."
            )

        if limit < 1:
            raise AuditValidationError(
                f"{field_name} must be greater than 0."
            )

        if limit > maximum:
            raise AuditValidationError(
                f"{field_name} must not exceed {maximum}."
            )

    @staticmethod
    def _validate_date_range(
        date_from: datetime | None,
        date_to: datetime | None,
    ) -> None:
        """
        Validate timezone-aware chronological date range.
        """

        if date_from is not None:

            if not isinstance(
                date_from,
                datetime,
            ):
                raise AuditValidationError(
                    "date_from must be a datetime."
                )

            if (
                date_from.tzinfo is None
                or date_from.utcoffset() is None
            ):
                raise AuditValidationError(
                    "date_from must be timezone-aware."
                )

        if date_to is not None:

            if not isinstance(
                date_to,
                datetime,
            ):
                raise AuditValidationError(
                    "date_to must be a datetime."
                )

            if (
                date_to.tzinfo is None
                or date_to.utcoffset() is None
            ):
                raise AuditValidationError(
                    "date_to must be timezone-aware."
                )

        if (
            date_from is not None
            and date_to is not None
            and date_from > date_to
        ):
            raise AuditValidationError(
                "date_from cannot be later than date_to."
            )

    # =========================================================================
    # Repository error handling
    # =========================================================================

    @staticmethod
    def _translate_repository_error(
        exc: Exception,
        message: str,
    ) -> None:
        """
        Translate repository exceptions into service exceptions.
        """

        if isinstance(
            exc,
            AuditRepositoryValidationError,
        ):
            raise AuditValidationError(
                str(exc),
            ) from exc

        if isinstance(
            exc,
            AuditRepositoryError,
        ):
            raise AuditServiceError(
                message,
            ) from exc

        raise exc

    # =========================================================================
    # Create
    # =========================================================================

    async def log(
        self,
        audit: AuditCreate,
    ):
        """
        Create one immutable audit event.

        Transaction ownership remains with the caller.
        """

        if not isinstance(
            audit,
            AuditCreate,
        ):
            raise AuditValidationError(
                "audit must be an AuditCreate instance."
            )

        payload = audit.model_copy(
            update={
                "metadata_json": self._prepare_metadata(
                    audit.metadata_json,
                )
            }
        )

        try:
            event = await self._repository.create(
                payload,
            )

            return await self._enrich_event(
                event,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to persist audit event.",
            )

    # =========================================================================
    # Detail lookup
    # =========================================================================

    async def get_event(
        self,
        audit_id: UUID,
    ):
        """
        Retrieve and enrich one immutable audit event.
        """

        self._validate_uuid(
            audit_id,
            field_name="audit_id",
        )

        try:
            event = await self._repository.get_event(
                audit_id,
            )

            if event is None:
                return None

            return await self._enrich_event(
                event,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to retrieve audit event.",
            )

    async def get_by_id(
        self,
        audit_id: UUID,
    ):
        """
        Backward-compatible alias.
        """

        return await self.get_event(
            audit_id,
        )

    async def get_audit_event(
        self,
        audit_id: UUID,
    ):
        """
        Backward-compatible alias.
        """

        return await self.get_event(
            audit_id,
        )

    # =========================================================================
    # Query filters
    # =========================================================================

    @classmethod
    def _prepare_query_filters(
        cls,
        *,
        action: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        source_ip: str | None = None,
        search: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Normalize and validate canonical Global Audit query filters.
        """

        cls._validate_date_range(
            date_from,
            date_to,
        )

        normalized_outcome = cls._optional_string(
            outcome,
            field_name="outcome",
            maximum=MAX_OUTCOME_LENGTH,
        )

        if normalized_outcome is not None:

            normalized_outcome = normalized_outcome.lower()

            if normalized_outcome not in CANONICAL_OUTCOMES:
                raise AuditValidationError(
                    "outcome must be one of: "
                    "success, failure, denied."
                )

        return {
            "action": cls._optional_string(
                action,
                field_name="action",
                maximum=MAX_ACTION_LENGTH,
            ),
            "category": cls._optional_string(
                category,
                field_name="category",
                maximum=MAX_CATEGORY_LENGTH,
            ),
            "outcome": normalized_outcome,
            "source_ip": cls._optional_string(
                source_ip,
                field_name="source_ip",
                maximum=MAX_SOURCE_IP_LENGTH,
            ),
            "search": cls._optional_string(
                search,
                field_name="search",
                maximum=MAX_SEARCH_LENGTH,
            ),
            "date_from": date_from,
            "date_to": date_to,
            "session_id": cls._optional_uuid(
                session_id,
                field_name="session_id",
            ),
            "request_id": cls._optional_string(
                request_id,
                field_name="request_id",
                maximum=MAX_REQUEST_ID_LENGTH,
            ),
        }

    # =========================================================================
    # Global list
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
    ):
        """
        Retrieve one page of globally visible audit events.

        Global Audit retains its full filtering capability.
        """

        self._validate_page(
            page,
        )

        self._validate_page_size(
            page_size,
        )

        actor_user_id = self._optional_uuid(
            actor_user_id,
            field_name="actor_user_id",
        )

        target_user_id = self._optional_uuid(
            target_user_id,
            field_name="target_user_id",
        )

        filters = self._prepare_query_filters(
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            search=search,
            date_from=date_from,
            date_to=date_to,
            session_id=session_id,
            request_id=request_id,
        )

        try:
            events, total = await self._repository.list_events(
                page=page,
                page_size=page_size,
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                **filters,
            )

            enriched_events = await self._enrich_events(
                events,
            )

            return (
                enriched_events,
                total,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to retrieve audit events.",
            )

    # =========================================================================
    # Individual User Audit
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
    ):
        """
        Retrieve paginated Individual User Audit history.

        Individual Audit filter contract:

            action
            outcome
            target_user_id
            source_ip
            date_from
            date_to

        The selected user remains the audit subject:

            actor_user_id = user_id
            OR
            target_user_id = user_id

        There is intentionally no:

            actor_user_id filter
            category filter
            search filter

        The frontend already establishes the selected user context,
        therefore actor is not a separate Individual Audit filter.

        The repository owns the actual SQL filtering.
        """

        user_id = self._validate_uuid(
            user_id,
            field_name="user_id",
        )

        self._validate_page(
            page,
        )

        self._validate_page_size(
            page_size,
        )

        target_user_id = self._optional_uuid(
            target_user_id,
            field_name="target_user_id",
        )

        normalized_action = self._optional_string(
            action,
            field_name="action",
            maximum=MAX_ACTION_LENGTH,
        )

        normalized_outcome = self._optional_string(
            outcome,
            field_name="outcome",
            maximum=MAX_OUTCOME_LENGTH,
        )

        if normalized_outcome is not None:

            normalized_outcome = normalized_outcome.lower()

            if normalized_outcome not in CANONICAL_OUTCOMES:
                raise AuditValidationError(
                    "outcome must be one of: "
                    "success, failure, denied."
                )

        normalized_source_ip = self._optional_string(
            source_ip,
            field_name="source_ip",
            maximum=MAX_SOURCE_IP_LENGTH,
        )

        self._validate_date_range(
            date_from,
            date_to,
        )

        try:

            events, total = await self._repository.get_user_events(
                user_id=user_id,
                page=page,
                page_size=page_size,
                action=normalized_action,
                outcome=normalized_outcome,
                target_user_id=target_user_id,
                source_ip=normalized_source_ip,
                date_from=date_from,
                date_to=date_to,
            )

            enriched_events = await self._enrich_events(
                events,
            )

            return (
                enriched_events,
                total,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to retrieve user audit history.",
            )

    # =========================================================================
    # Individual User Audit Statistics
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
        Return backend-authoritative statistics for the complete
        filtered Individual User Audit dataset.

        IMPORTANT:

        These statistics are NOT calculated from the currently
        paginated page.

        They are calculated from ALL audit events matching the
        selected user's Individual Audit scope and filters.

        Individual Audit scope:

            actor_user_id = user_id
            OR
            target_user_id = user_id

        Supported filters:

            action
            outcome
            target_user_id
            source_ip
            date_from
            date_to

        Actor is intentionally NOT an Individual Audit filter.

        Returns:

            {
                "total": int,
                "success": int,
                "failure": int,
                "denied": int,
            }

        Example:

            {
                "total": 143,
                "success": 30,
                "failure": 113,
                "denied": 0,
            }

        The repository performs the aggregate SQL query.
        The service validates the request and validates the
        repository response before returning it to the API layer.
        """

        user_id = self._validate_uuid(
            user_id,
            field_name="user_id",
        )

        target_user_id = self._optional_uuid(
            target_user_id,
            field_name="target_user_id",
        )

        normalized_action = self._optional_string(
            action,
            field_name="action",
            maximum=MAX_ACTION_LENGTH,
        )

        normalized_outcome = self._optional_string(
            outcome,
            field_name="outcome",
            maximum=MAX_OUTCOME_LENGTH,
        )

        if normalized_outcome is not None:

            normalized_outcome = normalized_outcome.lower()

            if normalized_outcome not in CANONICAL_OUTCOMES:
                raise AuditValidationError(
                    "outcome must be one of: "
                    "success, failure, denied."
                )

        normalized_source_ip = self._optional_string(
            source_ip,
            field_name="source_ip",
            maximum=MAX_SOURCE_IP_LENGTH,
        )

        self._validate_date_range(
            date_from,
            date_to,
        )

        try:

            statistics = await self._repository.get_user_statistics(
                user_id=user_id,
                action=normalized_action,
                outcome=normalized_outcome,
                target_user_id=target_user_id,
                source_ip=normalized_source_ip,
                date_from=date_from,
                date_to=date_to,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to calculate individual user audit statistics.",
            )

        if not isinstance(
            statistics,
            dict,
        ):
            raise AuditServiceError(
                "Repository returned invalid individual user "
                "audit statistics."
            )

        required_keys = (
            "total",
            "success",
            "failure",
            "denied",
        )

        normalized_statistics: dict[str, int] = {}

        for key in required_keys:

            value = statistics.get(
                key,
                0,
            )

            try:
                value = int(
                    value,
                )

            except (
                TypeError,
                ValueError,
            ) as exc:

                raise AuditServiceError(
                    "Repository returned an invalid individual "
                    f"user audit statistic: {key}."
                ) from exc

            if value < 0:
                raise AuditServiceError(
                    "Individual user audit statistic cannot "
                    f"be negative: {key}."
                )

            normalized_statistics[key] = value

        return normalized_statistics

    async def get_user_audit_statistics(
        self,
        user_id: UUID,
        **kwargs: Any,
    ) -> dict[str, int]:
        """
        Backward-compatible alias for Individual User Audit statistics.
        """

        return await self.get_user_statistics(
            user_id,
            **kwargs,
        )

    async def get_user_audit_history(
        self,
        user_id: UUID,
        **kwargs: Any,
    ):
        """
        Backward-compatible alias.
        """

        return await self.get_user_events(
            user_id,
            **kwargs,
        )

    # =========================================================================
    # Related events
    # =========================================================================

    async def get_related_events(
        self,
        audit_id: UUID,
        *,
        limit: int = DEFAULT_RELATED_LIMIT,
    ):
        """
        Retrieve and enrich events related to one audit event.
        """

        self._validate_uuid(
            audit_id,
            field_name="audit_id",
        )

        self._validate_limit(
            limit,
            maximum=MAX_RELATED_LIMIT,
        )

        try:

            events = await self._repository.get_related_events(
                audit_id,
                limit=limit,
            )

            return await self._enrich_events(
                events,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to retrieve related audit events.",
            )

    # =========================================================================
    # Session correlation
    # =========================================================================

    async def list_by_session(
        self,
        session_id: UUID,
        *,
        limit: int = DEFAULT_RELATED_LIMIT,
    ):
        """
        Retrieve events associated with one session.
        """

        self._validate_uuid(
            session_id,
            field_name="session_id",
        )

        self._validate_limit(
            limit,
            maximum=MAX_RELATED_LIMIT,
        )

        try:

            events = await self._repository.list_by_session(
                session_id,
                limit=limit,
            )

            return await self._enrich_events(
                events,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to retrieve session audit events.",
            )

    # =========================================================================
    # Request correlation
    # =========================================================================

    async def list_by_request(
        self,
        request_id: str,
        *,
        limit: int = DEFAULT_RELATED_LIMIT,
    ):
        """
        Retrieve events associated with one request ID.
        """

        request_id = self._validate_string(
            request_id,
            field_name="request_id",
        )

        if len(request_id) > MAX_REQUEST_ID_LENGTH:
            raise AuditValidationError(
                "request_id exceeds maximum length of "
                f"{MAX_REQUEST_ID_LENGTH}."
            )

        self._validate_limit(
            limit,
            maximum=MAX_RELATED_LIMIT,
        )

        try:

            events = await self._repository.list_by_request(
                request_id,
                limit=limit,
            )

            return await self._enrich_events(
                events,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to retrieve request audit events.",
            )

    # =========================================================================
    # Count
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
        """
        Count events using canonical repository filters.
        """

        filters = self._prepare_query_filters(
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            search=search,
            date_from=date_from,
            date_to=date_to,
            session_id=session_id,
            request_id=request_id,
        )

        try:

            result = await self._repository.count_events(
                actor_user_id=self._optional_uuid(
                    actor_user_id,
                    field_name="actor_user_id",
                ),
                target_user_id=self._optional_uuid(
                    target_user_id,
                    field_name="target_user_id",
                ),
                **filters,
            )

            return int(
                result,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to count audit events.",
            )

    # =========================================================================
    # Global Statistics
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
        """
        Return backend-authoritative global audit statistics.
        """

        filters = self._prepare_query_filters(
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            search=search,
            date_from=date_from,
            date_to=date_to,
            session_id=session_id,
            request_id=request_id,
        )

        try:

            statistics = await self._repository.get_statistics(
                actor_user_id=self._optional_uuid(
                    actor_user_id,
                    field_name="actor_user_id",
                ),
                target_user_id=self._optional_uuid(
                    target_user_id,
                    field_name="target_user_id",
                ),
                **filters,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to calculate audit statistics.",
            )

        if not isinstance(
            statistics,
            dict,
        ):
            raise AuditServiceError(
                "Repository returned invalid audit statistics."
            )

        keys = (
            "total",
            "success",
            "failure",
            "denied",
            "unique_actors",
            "unique_targets",
        )

        result: dict[str, int] = {}

        for key in keys:

            try:
                value = int(
                    statistics.get(
                        key,
                        0,
                    )
                )

            except (
                TypeError,
                ValueError,
            ) as exc:

                raise AuditServiceError(
                    f"Invalid audit statistic: {key}."
                ) from exc

            if value < 0:
                raise AuditServiceError(
                    f"Audit statistic cannot be negative: {key}."
                )

            result[key] = value

        return result

    async def statistics(
        self,
        **kwargs: Any,
    ) -> dict[str, int]:
        """
        Backward-compatible statistics alias.
        """

        return await self.get_statistics(
            **kwargs,
        )

    # =========================================================================
    # User activity
    # =========================================================================

    async def get_user_activity(
        self,
        user_id: UUID,
        *,
        limit: int = DEFAULT_RECENT_LIMIT,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        session_id: UUID | None = None,
        request_id: str | None = None,
    ):
        """
        Retrieve recent user activity with identity enrichment.
        """

        self._validate_uuid(
            user_id,
            field_name="user_id",
        )

        self._validate_limit(
            limit,
            maximum=MAX_RECENT_LIMIT,
        )

        self._validate_date_range(
            date_from,
            date_to,
        )

        try:

            events = await self._repository.get_user_activity(
                user_id,
                limit=limit,
                date_from=date_from,
                date_to=date_to,
                session_id=self._optional_uuid(
                    session_id,
                    field_name="session_id",
                ),
                request_id=self._optional_string(
                    request_id,
                    field_name="request_id",
                    maximum=MAX_REQUEST_ID_LENGTH,
                ),
            )

            return await self._enrich_events(
                events,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to retrieve user activity.",
            )

    async def get_recent_user_activity(
        self,
        user_id: UUID,
        **kwargs: Any,
    ):
        """
        Backward-compatible alias.
        """

        return await self.get_user_activity(
            user_id,
            **kwargs,
        )

    # =========================================================================
    # Export
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
    ):
        """
        Retrieve bounded audit events for export.
        """

        self._validate_limit(
            limit,
            maximum=MAX_EXPORT_LIMIT,
        )

        filters = self._prepare_query_filters(
            action=action,
            category=category,
            outcome=outcome,
            source_ip=source_ip,
            search=search,
            date_from=date_from,
            date_to=date_to,
            session_id=session_id,
            request_id=request_id,
        )

        try:

            events = await self._repository.get_export_events(
                actor_user_id=self._optional_uuid(
                    actor_user_id,
                    field_name="actor_user_id",
                ),
                target_user_id=self._optional_uuid(
                    target_user_id,
                    field_name="target_user_id",
                ),
                limit=limit,
                **filters,
            )

            return await self._enrich_events(
                events,
            )

        except (
            AuditRepositoryValidationError,
            AuditRepositoryError,
        ) as exc:

            self._translate_repository_error(
                exc,
                "Unable to export audit events.",
            )

    async def export_events(
        self,
        **kwargs: Any,
    ):
        """
        Backward-compatible export alias.
        """

        return await self.get_export_events(
            **kwargs,
        )

    async def export(
        self,
        **kwargs: Any,
    ):
        """
        Backward-compatible export alias.
        """

        return await self.get_export_events(
            **kwargs,
        )


# =============================================================================
# Public exports
# =============================================================================


__all__ = [
    "AuditService",
    "AuditServiceError",
    "AuditValidationError",
]