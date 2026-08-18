from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta
import logging
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts.manager import AlertManager
from app.api.websocket.publisher import WebSocketPublisher
from app.auth.adapters import (
    PostgresAuthAuditRepository,
    PostgresSessionRepository,
    PostgresUserRepository,
)
from app.auth.audit import AuditSink, InMemoryAuditSink
from app.auth.authentication import (
    AuthenticationError,
    AuthenticationService,
)
from app.auth.authorization import (
    AuthorizationService,
    PermissionDenied,
)
from app.auth.models import AuditRecord
from app.auth.password import PasswordHasher
from app.auth.roles import RoleRegistry
from app.auth.tokens import TokenService
from app.incidents.manager import IncidentManager
from app.storage.postgres.session import PostgresSessionManager
from app.threat_intelligence.service import ThreatIntelligenceService


logger = logging.getLogger(__name__)


# ============================================================================
# Defaults
# ============================================================================

DEFAULT_AUTH_SESSION_TTL = timedelta(minutes=30)
DEFAULT_AUTH_TOKEN_TTL = timedelta(minutes=30)


# ============================================================================
# Bearer authentication
# ============================================================================

bearer_scheme = HTTPBearer(
    auto_error=False,
)


# ============================================================================
# API dependency container
# ============================================================================


@dataclass(slots=True)
class APIContainer:
    """
    Central application dependency container.

    Application-scoped dependencies are stored here.

    IMPORTANT:
    AsyncSession is intentionally NOT stored in this container.
    Database sessions are request-scoped and are created through
    get_db_session().
    """

    # ------------------------------------------------------------------------
    # Existing Phase 15 dependencies
    # ------------------------------------------------------------------------

    event_repository: Any | None = None

    alert_manager: AlertManager | None = None

    incident_manager: IncidentManager | None = None

    threat_intelligence: ThreatIntelligenceService | None = None

    mitre_service: Any | None = None

    # ------------------------------------------------------------------------
    # Realtime WebSocket publisher
    # ------------------------------------------------------------------------

    websocket_publisher: WebSocketPublisher | None = None

    # ------------------------------------------------------------------------
    # Phase 17 application-scoped dependencies
    # ------------------------------------------------------------------------

    password_hasher: PasswordHasher | None = None

    token_service: TokenService | None = None

    role_registry: RoleRegistry | None = None

    authorization_service: AuthorizationService | None = None

    # ------------------------------------------------------------------------
    # PostgreSQL lifecycle
    # ------------------------------------------------------------------------

    postgres_session_manager: PostgresSessionManager | None = None

    # ------------------------------------------------------------------------
    # Development fallback audit sink
    # ------------------------------------------------------------------------

    audit_sink: AuditSink | None = None

    # ------------------------------------------------------------------------
    # Authentication/session configuration
    # ------------------------------------------------------------------------

    auth_session_ttl: timedelta = DEFAULT_AUTH_SESSION_TTL

    auth_token_ttl: timedelta = DEFAULT_AUTH_TOKEN_TTL

    # ------------------------------------------------------------------------
    # Backward-compatible externally supplied services
    # ------------------------------------------------------------------------

    user_repository: Any | None = None

    authentication_service: AuthenticationService | None = None

    def __post_init__(self) -> None:
        """
        Initialize safe application-scoped defaults.

        Request-scoped PostgreSQL repositories are intentionally NOT created
        here.
        """

        # --------------------------------------------------------------------
        # Existing Phase 15 defaults
        # --------------------------------------------------------------------

        if self.alert_manager is None:
            self.alert_manager = AlertManager()

        if self.incident_manager is None:
            self.incident_manager = IncidentManager()

        if self.threat_intelligence is None:
            self.threat_intelligence = ThreatIntelligenceService()

        # --------------------------------------------------------------------
        # Phase 17 defaults
        # --------------------------------------------------------------------

        if self.password_hasher is None:
            self.password_hasher = PasswordHasher()

        if self.role_registry is None:
            self.role_registry = RoleRegistry()

        if self.audit_sink is None:
            self.audit_sink = InMemoryAuditSink()

        if self.authorization_service is None:
            self.authorization_service = AuthorizationService(
                role_registry=self.role_registry,
                audit=self.audit_sink,
            )


# ============================================================================
# API container resolver
# ============================================================================


def get_api_container(
    request: Request,
) -> APIContainer:
    """
    Resolve the application dependency container.
    """
    container = getattr(
        request.app.state,
        "api",
        None,
    )

    if not isinstance(container, APIContainer):
        raise RuntimeError(
            "API dependency container is not configured."
        )

    return container


# ============================================================================
# WebSocket realtime publisher resolver
# ============================================================================


def get_websocket_publisher(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> WebSocketPublisher:
    """
    Resolve the application-scoped realtime WebSocket publisher.
    """
    publisher = container.websocket_publisher

    if publisher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Realtime WebSocket publisher is not configured.",
        )

    return publisher


# ============================================================================
# PostgreSQL session manager resolver
# ============================================================================


def get_postgres_session_manager(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> PostgresSessionManager:
    """
    Resolve the application PostgreSQL session manager.
    """
    manager = container.postgres_session_manager

    if manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PostgreSQL storage is not configured.",
        )

    return manager


# ============================================================================
# Request-scoped PostgreSQL AsyncSession
# ============================================================================


async def get_db_session(
    manager: PostgresSessionManager = Depends(
        get_postgres_session_manager,
    ),
) -> AsyncIterator[AsyncSession]:
    """
    Provide one AsyncSession per HTTP request.

    Transaction lifecycle:

        request success
            -> COMMIT

        request exception
            -> ROLLBACK

        always
            -> CLOSE
    """
    async with manager.session() as session:
        try:
            yield session
            await session.commit()

        except Exception:
            await session.rollback()
            raise


# ============================================================================
# Request metadata helpers
# ============================================================================


def _request_id(
    request: Request,
) -> str | None:
    """
    Resolve the current request ID defensively.
    """
    value = getattr(
        request.state,
        "request_id",
        None,
    )

    if value is None:
        return None

    normalized = str(value).strip()

    return normalized or None


def _source_ip(
    request: Request,
) -> str | None:
    """
    Resolve the client source IP defensively.
    """
    client = request.client

    if client is None:
        return None

    host = getattr(
        client,
        "host",
        None,
    )

    if host is None:
        return None

    normalized = str(host).strip()

    return normalized or None


# ============================================================================
# Durable independent authentication audit sink
# ============================================================================


class _PostgresDurableAuthAuditSink:
    """
    Persist authentication audit events using an independent transaction.

    This adapter exists specifically for security-sensitive authentication
    failure events.

    Why is this separate from PostgresAuthAuditRepository?

    The normal request-scoped AsyncSession is committed by get_db_session()
    only when the request completes successfully.

    A failed login produces HTTP 401, which causes the normal request
    transaction to roll back.

    Therefore:

        normal request session
            |
            +--> login failure audit
            |
            +--> HTTP 401
            |
            +--> ROLLBACK
                    |
                    +--> audit disappears

    This sink instead creates:

        independent AsyncSession
            |
            +--> audit record
            |
            +--> COMMIT
            |
            +--> survives request rollback

    It intentionally implements the small ``record()`` interface required
    by AuthenticationService.
    """

    def __init__(
        self,
        manager: PostgresSessionManager,
    ) -> None:
        self._manager = manager

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """
        Persist one audit record and commit it independently.

        Any exception is allowed to propagate to AuthenticationService,
        which deliberately treats audit persistence failure as non-fatal to
        the authentication response.
        """
        async with self._manager.session() as audit_session:
            repository = PostgresAuthAuditRepository(
                audit_session,
            )

            await repository.record(
                record,
            )

            await audit_session.commit()


# ============================================================================
# Durable authorization audit
# ============================================================================


async def _record_authorization_audit(
    *,
    request: Request,
    manager: PostgresSessionManager | None,
    action: str,
    principal: Any | None,
    metadata: dict[str, Any],
) -> None:
    """
    Persist an authorization audit event using an independent transaction.

    Authorization failures return HTTP 403.
    Therefore the request-scoped database transaction may be rolled back.

    Authorization audit records must survive that rollback.
    """
    if manager is None:
        return

    audit_record = AuditRecord(
        action=action,
        outcome="failure",
        actor_user_id=(
            principal.user_id
            if principal is not None
            else None
        ),
        session_id=(
            principal.session_id
            if principal is not None
            else None
        ),
        request_id=_request_id(request),
        source_ip=_source_ip(request),
        metadata=metadata,
    )

    try:
        async with manager.session() as audit_session:
            repository = PostgresAuthAuditRepository(
                audit_session,
            )

            await repository.record(
                audit_record,
            )

            await audit_session.commit()

    except Exception:
        # Never bypass authorization because audit persistence failed.
        #
        # The caller will still return HTTP 403.
        logger.exception(
            "Unable to persist authorization audit event.",
            extra={
                "authorization_action": action,
                "authorization_metadata": metadata,
                "actor_user_id": (
                    str(principal.user_id)
                    if principal is not None
                    else None
                ),
                "session_id": (
                    str(principal.session_id)
                    if principal is not None
                    else None
                ),
                "request_id": _request_id(request),
                "source_ip": _source_ip(request),
            },
        )


# ============================================================================
# Authentication service construction
# ============================================================================


def _build_authentication_service(
    *,
    session: AsyncSession,
    container: APIContainer,
) -> AuthenticationService:
    """
    Build a request-scoped AuthenticationService.

    Normal authentication repositories use the request-scoped AsyncSession.

    Failed-login auditing uses a separate durable audit sink backed by a
    completely independent AsyncSession.
    """

    # ------------------------------------------------------------------------
    # Validate required application dependencies
    # ------------------------------------------------------------------------

    if container.token_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication token service is not configured.",
        )

    if container.password_hasher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication password service is not configured.",
        )

    if container.role_registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication role registry is not configured.",
        )

    # ------------------------------------------------------------------------
    # Request-scoped repositories
    # ------------------------------------------------------------------------

    users = PostgresUserRepository(
        session,
    )

    sessions = PostgresSessionRepository(
        session,
    )

    audit = PostgresAuthAuditRepository(
        session,
    )

    # ------------------------------------------------------------------------
    # Independent durable failed-login audit
    # ------------------------------------------------------------------------

    failure_audit: AuditSink | Any | None = None

    if container.postgres_session_manager is not None:
        failure_audit = _PostgresDurableAuthAuditSink(
            container.postgres_session_manager,
        )
    else:
        # PostgreSQL is required by get_authentication_service(), so this
        # branch is defensive only.
        failure_audit = container.audit_sink

    # ------------------------------------------------------------------------
    # Authentication service
    # ------------------------------------------------------------------------

    return AuthenticationService(
        users=users,
        tokens=container.token_service,
        sessions=sessions,
        password_hasher=container.password_hasher,
        audit=audit,
        failure_audit=failure_audit,
        roles=container.role_registry,
        session_ttl=container.auth_session_ttl,
    )


# ============================================================================
# Authentication service dependency
# ============================================================================


def get_authentication_service(
    request: Request,
    session: AsyncSession = Depends(
        get_db_session,
    ),
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> AuthenticationService:
    """
    Resolve a request-scoped PostgreSQL-backed AuthenticationService.

    Every request gets repositories bound to its own AsyncSession.

    Failed-login auditing is additionally backed by an independent session.
    """
    del request

    if container.postgres_session_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication storage is not configured.",
        )

    return _build_authentication_service(
        session=session,
        container=container,
    )


# ============================================================================
# Authorization service
# ============================================================================


def get_authorization_service(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> AuthorizationService:
    """
    Resolve the centralized authorization service.
    """
    service = container.authorization_service

    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization service is not configured.",
        )

    return service


# ============================================================================
# Bearer token extraction
# ============================================================================


def get_bearer_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme,
    ),
) -> str:
    """
    Extract a Bearer access token.

    Missing or malformed authentication is normalized to HTTP 401.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    token = credentials.credentials.strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return token


# ============================================================================
# Current authenticated principal
# ============================================================================


async def get_current_principal(
    token: str = Depends(
        get_bearer_token,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
):
    """
    Authenticate and resolve the current principal.

    Validation includes:

    - JWT signature
    - allowed algorithm
    - issuer
    - audience
    - required claims
    - expiration
    - session existence
    - session expiration
    - session revocation
    - user existence
    - user active state
    - user locked state
    - token/session binding
    - user/session binding
    """
    try:
        return await authentication.authenticate_token(
            token,
        )

    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from None


# ============================================================================
# Explicit authenticated-user dependency
# ============================================================================


async def require_authenticated_user(
    principal=Depends(
        get_current_principal,
    ),
):
    """
    Require a valid authenticated principal.
    """
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return principal


# ============================================================================
# Permission dependency factory
# ============================================================================


def require_permission(
    permission: str,
):
    """
    Create a dependency requiring a specific permission.

    Example:

        Depends(require_permission("events:read"))
    """
    normalized_permission = permission.strip()

    if not normalized_permission:
        raise ValueError(
            "Permission name cannot be empty."
        )

    async def dependency(
        request: Request,
        principal=Depends(
            get_current_principal,
        ),
        authorization: AuthorizationService = Depends(
            get_authorization_service,
        ),
        container: APIContainer = Depends(
            get_api_container,
        ),
    ):
        try:
            return authorization.require_permission(
                principal,
                normalized_permission,
            )

        except PermissionDenied as exc:
            await _record_authorization_audit(
                request=request,
                manager=container.postgres_session_manager,
                action="authorization.denied",
                principal=principal,
                metadata={
                    "permission": normalized_permission,
                    "reason": exc.reason,
                },
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied.",
            ) from None

    return dependency


# ============================================================================
# Role dependency factory
# ============================================================================


def require_role(
    role: str,
):
    """
    Create a dependency requiring a specific role.

    Example:

        Depends(require_role("ADMIN"))
    """
    normalized_role = role.strip()

    if not normalized_role:
        raise ValueError(
            "Role name cannot be empty."
        )

    async def dependency(
        request: Request,
        principal=Depends(
            get_current_principal,
        ),
        authorization: AuthorizationService = Depends(
            get_authorization_service,
        ),
        container: APIContainer = Depends(
            get_api_container,
        ),
    ):
        try:
            return authorization.require_role(
                principal,
                normalized_role,
            )

        except PermissionDenied as exc:
            await _record_authorization_audit(
                request=request,
                manager=container.postgres_session_manager,
                action="authorization.denied",
                principal=principal,
                metadata={
                    "role": normalized_role,
                    "reason": exc.reason,
                },
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Role requirement not satisfied.",
            ) from None

    return dependency


# ============================================================================
# Optional authenticated principal
# ============================================================================


async def get_optional_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
):
    """
    Resolve an optional authenticated principal.

    No credentials:
        -> None

    Valid credentials:
        -> UserPrincipal

    Invalid supplied credentials:
        -> HTTP 401
    """
    if credentials is None:
        return None

    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    token = credentials.credentials.strip()

    if not token:
        return None

    try:
        return await authentication.authenticate_token(
            token,
        )

    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from None