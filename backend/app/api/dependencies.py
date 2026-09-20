from __future__ import annotations

import logging

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts.manager import AlertManager
from app.alerts.service import AlertService

from app.api.websocket.publisher import WebSocketPublisher

from app.audit.schemas import AuditCreate
from app.audit.service import (
    AuditService,
    AuditServiceError,
    AuditValidationError,
)

from app.assets.repository import AssetRepository
from app.assets.service import AssetService

from app.auth.authentication import (
    AuthenticationError,
    AuthenticationService,
)

from app.auth.authorization import (
    AuthorizationService,
    PermissionDenied,
)

from app.auth.models import AuditRecord, UserPrincipal
from app.auth.password import PasswordHasher
from app.auth.permissions import Permission
from app.auth.roles import Role, RoleRegistry
from app.auth.tokens import TokenService
from app.auth.user_management import UserManagementService

from app.core.config import get_settings

from app.detection.engine import DetectionEngine
from app.detection.service import DetectionService

from app.incidents.manager import IncidentManager

from app.mitre.manager import MitreManager
from app.mitre.service import MitreService

from app.storage.opensearch.alerts import (
    OpenSearchAlertRepository,
)

from app.storage.opensearch.client import (
    OpenSearchClient,
)

from app.storage.opensearch.detections import (
    OpenSearchDetectionRepository,
)

from app.storage.opensearch.incidents import (
    OpenSearchIncidentRepository,
)

from app.storage.opensearch.mitre import (
    MitreMappingRepository,
)

from app.storage.postgres.ioc_repository import (
    IOCRepository,
)

from app.storage.postgres.session import (
    PostgresSessionManager,
)

from app.mitre.repository import MitreRepository

from app.threat_intelligence.service import (
    ThreatIntelligenceService,
)


# =============================================================================
# Logger
# =============================================================================

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

DEFAULT_AUTH_SESSION_TTL = timedelta(
    minutes=30,
)

DEFAULT_AUTH_TOKEN_TTL = timedelta(
    minutes=30,
)

MAX_REQUEST_ID_LENGTH = 100
MAX_SOURCE_IP_LENGTH = 45
MAX_USER_AGENT_LENGTH = 1000


# =============================================================================
# Bearer Authentication
# =============================================================================

bearer_scheme = HTTPBearer(
    auto_error=False,
)


# =============================================================================
# API Container
# =============================================================================


@dataclass(slots=True)
class APIContainer:
    """
    Application-scoped dependency container.

    Application-scoped dependencies include:

        - AlertManager
        - AlertService
        - IncidentManager
        - Threat Intelligence runtime
        - MITRE runtime
        - PasswordHasher
        - TokenService
        - RoleRegistry
        - AuthorizationService
        - DetectionService
        - DetectionEngine
        - WebSocketPublisher
        - PostgreSQL session manager

    Request-scoped dependencies are intentionally NOT stored here.

    Request-scoped dependencies include:

        - AsyncSession
        - OpenSearch repositories
        - IOCRepository
        - AssetRepository
        - AssetService
        - request-scoped ThreatIntelligenceService
        - AuthenticationService
        - UserManagementService
        - AuditService
    """

    # -------------------------------------------------------------------------
    # Application services
    # -------------------------------------------------------------------------

    event_repository: Any | None = None

    alert_manager: AlertManager | None = None

    alert_service: AlertService | None = None

    incident_manager: IncidentManager | None = None

    threat_intelligence: ThreatIntelligenceService | None = None

    # -------------------------------------------------------------------------
    # MITRE ATT&CK
    # -------------------------------------------------------------------------

    # Existing Detection → MITRE mapping repository.
    #
    # This is NOT the authoritative MITRE ATT&CK knowledge repository.
    mitre_repository: MitreMappingRepository | None = None

    # Existing OpenSearch client used by the mapping runtime.
    mitre_opensearch_client: OpenSearchClient | None = None

    # Application-scoped Detection → MITRE mapping manager.
    #
    # The manager owns the in-memory mapping registry and coverage runtime.
    # It does NOT own authoritative MITRE ATT&CK knowledge.
    mitre_manager: MitreManager | None = None

    # MITRE service is request-scoped because authoritative ATT&CK knowledge
    # is backed by the request-scoped PostgreSQL AsyncSession.
    mitre_service: MitreService | None = None

    # -------------------------------------------------------------------------
    # Detection
    # -------------------------------------------------------------------------

    detection_service: DetectionService | None = None

    detection_engine: DetectionEngine | None = None

    # -------------------------------------------------------------------------
    # Realtime
    # -------------------------------------------------------------------------

    websocket_publisher: WebSocketPublisher | None = None

    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------

    password_hasher: PasswordHasher | None = None

    token_service: TokenService | None = None

    role_registry: RoleRegistry | None = None

    authorization_service: AuthorizationService | None = None

    # -------------------------------------------------------------------------
    # PostgreSQL
    # -------------------------------------------------------------------------

    postgres_session_manager: PostgresSessionManager | None = None

    # -------------------------------------------------------------------------
    # Legacy authentication audit compatibility
    # -------------------------------------------------------------------------

    audit_sink: Any | None = None

    # -------------------------------------------------------------------------
    # Authentication configuration
    # -------------------------------------------------------------------------

    auth_session_ttl: timedelta = DEFAULT_AUTH_SESSION_TTL

    auth_token_ttl: timedelta = DEFAULT_AUTH_TOKEN_TTL

    # -------------------------------------------------------------------------
    # Legacy compatibility
    # -------------------------------------------------------------------------

    user_repository: Any | None = None

    authentication_service: AuthenticationService | None = None

    # =========================================================================
    # Initialization
    # =========================================================================

    def __post_init__(self) -> None:
        """
        Initialize application-scoped defaults.

        Request-scoped PostgreSQL and OpenSearch resources are never created
        here.
        """

        # ---------------------------------------------------------------------
        # Alert runtime
        # ---------------------------------------------------------------------

        if self.alert_manager is None:
            self.alert_manager = AlertManager()

        if self.alert_service is None:
            self.alert_service = AlertService(
                manager=self.alert_manager,
            )

        # ---------------------------------------------------------------------
        # Incident runtime
        # ---------------------------------------------------------------------

        if self.incident_manager is None:
            self.incident_manager = IncidentManager()

        # ---------------------------------------------------------------------
        # Threat Intelligence runtime
        # ---------------------------------------------------------------------

        if self.threat_intelligence is None:
            self.threat_intelligence = ThreatIntelligenceService()

        # ---------------------------------------------------------------------
        # Authentication
        # ---------------------------------------------------------------------

        if self.password_hasher is None:
            self.password_hasher = PasswordHasher()

        if self.role_registry is None:
            self.role_registry = RoleRegistry()

        if self.authorization_service is None:
            self.authorization_service = AuthorizationService(
                role_registry=self.role_registry,
                audit=self.audit_sink,
            )

    # =========================================================================
    # MITRE Runtime
    # =========================================================================

    async def initialize_mitre_runtime(
        self,
    ) -> MitreService:
        """
        Initialize the application-scoped Detection → MITRE mapping runtime.

        Architecture:

            OpenSearch client
                    ↓
            MitreMappingRepository
                    ↓
              MitreManager
                    ↓
            MappingRegistry
                    ↓
              MitreService

        Important:

        This runtime is responsible for SentinelSIEM detection mappings and
        coverage calculations.

        It is NOT the authoritative source for MITRE ATT&CK knowledge.

        MITRE ATT&CK knowledge is intended to be supplied by:

            enterprise-attack.json
                    ↓
                importer
                    ↓
                PostgreSQL
                    ↓
              MITRE knowledge repository
        """

        if (
            self.mitre_manager is not None
            and self.mitre_repository is not None
        ):
            return self.mitre_manager

        # ---------------------------------------------------------------------
        # OpenSearch client
        # ---------------------------------------------------------------------

        if self.mitre_opensearch_client is None:
            self.mitre_opensearch_client = _build_opensearch_client()

        # ---------------------------------------------------------------------
        # Detection → MITRE mapping repository
        # ---------------------------------------------------------------------

        if self.mitre_repository is None:
            self.mitre_repository = MitreMappingRepository(
                self.mitre_opensearch_client.client,
            )

        # ---------------------------------------------------------------------
        # MITRE mapping manager
        # ---------------------------------------------------------------------

        manager = MitreManager(
            repository=self.mitre_repository,
        )

        # Keep the mapping manager application-scoped.
        #
        # The PostgreSQL MITRE knowledge repository cannot be created here
        # because initialize_mitre_runtime() has no request-scoped AsyncSession.
        self.mitre_manager = manager

        # ---------------------------------------------------------------------
        # Hydrate persisted mappings
        # ---------------------------------------------------------------------

        try:
            hydrated = await manager.hydrate()

        except Exception:
            logger.exception(
                "Failed to hydrate MITRE detection mappings from OpenSearch.",
            )

            await self.shutdown_mitre_runtime()

            raise

        # ---------------------------------------------------------------------
        # MITRE application service
        # ---------------------------------------------------------------------
        #
        # MitreService is request-scoped and is created by get_mitre_service()
        # with:
        #
        #     MitreRepository(AsyncSession)
        #     +
        #     application-scoped MitreManager
        #
        # Therefore it must NOT be constructed here.

        logger.info(
            "MITRE mapping runtime initialized: "
            "%d persisted mappings hydrated.",
            hydrated,
        )

        return self.mitre_manager

    async def shutdown_mitre_runtime(
        self,
    ) -> None:
        """
        Shutdown the application-scoped MITRE mapping runtime.
        """

        self.mitre_service = None
        self.mitre_manager = None
        self.mitre_repository = None

        client = self.mitre_opensearch_client

        self.mitre_opensearch_client = None

        if client is not None:
            try:
                await client.close()

            except Exception:
                logger.exception(
                    "Failed to close MITRE OpenSearch client.",
                )


# =============================================================================
# API Container Resolver
# =============================================================================


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

    if not isinstance(
        container,
        APIContainer,
    ):
        raise RuntimeError(
            "API dependency container is not configured.",
        )

    return container


# =============================================================================
# OpenSearch Client Builder
# =============================================================================


def _build_opensearch_client() -> OpenSearchClient:
    """
    Build an OpenSearch client from centralized application settings.
    """

    settings = get_settings()

    if not settings.opensearch_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenSearch is not configured.",
        )

    if not settings.opensearch_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenSearch URL is not configured.",
        )

    if not settings.opensearch_password:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenSearch credentials are not configured.",
        )

    parsed = urlparse(
        settings.opensearch_url,
    )

    if parsed.hostname is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenSearch URL must contain a valid hostname.",
        )

    scheme = parsed.scheme.lower()

    if scheme not in {
        "http",
        "https",
    }:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "OpenSearch URL must use "
                "the http or https scheme."
            ),
        )

    use_ssl = scheme == "https"

    port = parsed.port

    if port is None:
        port = 443 if use_ssl else 80

    return OpenSearchClient(
        hosts=[
            {
                "host": parsed.hostname,
                "port": port,
            },
        ],
        username=settings.opensearch_username,
        password=settings.opensearch_password,
        use_ssl=use_ssl,
        verify_certs=settings.opensearch_verify_certs,
        ca_certs=settings.opensearch_ca_certs,
    )


# =============================================================================
# MITRE Mapping Repository
# =============================================================================


def get_mitre_repository(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> MitreMappingRepository:
    """
    Resolve the application-scoped Detection → MITRE mapping repository.

    This repository is backed by OpenSearch.

    It must not be confused with the authoritative MITRE ATT&CK knowledge
    repository backed by PostgreSQL.
    """

    repository = container.mitre_repository

    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "MITRE mapping repository "
                "is not initialized."
            ),
        )

    return repository


# =============================================================================
# MITRE Authorization
# =============================================================================




# =============================================================================
# Alert Repository
# =============================================================================


async def get_alert_repository(
) -> AsyncIterator[OpenSearchAlertRepository]:
    """
    Resolve a request-scoped OpenSearch alert repository.
    """

    client = _build_opensearch_client()

    repository = OpenSearchAlertRepository(
        client.client,
    )

    try:
        yield repository

    finally:
        await client.close()


# =============================================================================
# Detection Repository
# =============================================================================


async def get_detection_repository(
) -> AsyncIterator[OpenSearchDetectionRepository]:
    """
    Resolve a request-scoped OpenSearch DetectionResult repository.
    """

    client = _build_opensearch_client()

    repository = OpenSearchDetectionRepository(
        client.client,
    )

    try:
        yield repository

    finally:
        await client.close()


# =============================================================================
# Incident Repository
# =============================================================================


async def get_incident_repository(
) -> AsyncIterator[OpenSearchIncidentRepository]:
    """
    Resolve a request-scoped OpenSearch incident repository.
    """

    client = _build_opensearch_client()

    repository = OpenSearchIncidentRepository(
        client.client,
    )

    try:
        yield repository

    finally:
        await client.close()


# =============================================================================
# PostgreSQL Session Manager
# =============================================================================


def get_postgres_session_manager(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> PostgresSessionManager:
    """
    Resolve the application-scoped PostgreSQL session manager.
    """

    manager = container.postgres_session_manager

    if manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "PostgreSQL storage "
                "is not configured."
            ),
        )

    return manager


# =============================================================================
# PostgreSQL Session
# =============================================================================


async def get_db_session(
    manager: PostgresSessionManager = Depends(
        get_postgres_session_manager,
    ),
) -> AsyncIterator[AsyncSession]:
    """
    Provide one AsyncSession per request.

    Transaction behavior:

        success
            → commit

        exception
            → rollback
    """

    async with manager.session() as session:
        try:
            yield session

        except Exception:
            await session.rollback()
            raise

        else:
            await session.commit()


# =============================================================================
# MITRE Service
# =============================================================================


def get_mitre_service(
    session: AsyncSession = Depends(
        get_db_session,
    ),
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> MitreService:
    """
    Resolve a request-scoped MITRE service.

    Architecture:

        Request
            ↓
        AsyncSession
            ↓
        MitreRepository
            ↓
        MitreService
            ↑
        MitreManager
            ↓
        Detection → MITRE mappings

    MITRE ATT&CK knowledge is read from PostgreSQL through the
    request-scoped MitreRepository.

    Detection → MITRE mapping runtime remains application-scoped
    through MitreManager.
    """

    manager = container.mitre_manager

    if manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "MITRE mapping manager "
                "is not initialized."
            ),
        )

    repository = MitreRepository(
        session,
    )

    return MitreService(
        repository=repository,
        manager=manager,
    )

# =============================================================================
# Asset Repository
# =============================================================================


def get_asset_repository(
    session: AsyncSession = Depends(
        get_db_session,
    ),
) -> AssetRepository:
    """
    Resolve a request-scoped AssetRepository.
    """

    return AssetRepository(
        session,
    )


# =============================================================================
# Asset Service
# =============================================================================


def get_asset_service(
    repository: AssetRepository = Depends(
        get_asset_repository,
    ),
) -> AssetService:
    """
    Resolve a request-scoped AssetService.

    Dependency chain:

        API route
            ↓
        AssetService
            ↓
        AssetRepository
            ↓
        AsyncSession
    """

    return AssetService(
        repository,
    )


# =============================================================================
# IOC Repository
# =============================================================================


def get_ioc_repository(
    session: AsyncSession = Depends(
        get_db_session,
    ),
) -> IOCRepository:
    """
    Resolve the request-scoped PostgreSQL IOC repository.
    """

    return IOCRepository(
        session,
    )


# =============================================================================
# WebSocket Publisher
# =============================================================================


def get_websocket_publisher(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> WebSocketPublisher:
    """
    Resolve application-scoped WebSocket publisher.
    """

    publisher = container.websocket_publisher

    if publisher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Realtime WebSocket publisher "
                "is not configured."
            ),
        )

    return publisher


# =============================================================================
# Alert Manager
# =============================================================================


def get_alert_manager(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> AlertManager:
    """
    Resolve the shared application-scoped AlertManager.
    """

    manager = container.alert_manager

    if manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Alert manager is not configured.",
        )

    return manager


# =============================================================================
# Alert Service
# =============================================================================


def get_alert_service(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> AlertService:
    """
    Resolve the shared application-scoped AlertService.
    """

    service = container.alert_service

    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Alert service is not configured.",
        )

    return service


# =============================================================================
# Incident Manager
# =============================================================================


def get_incident_manager(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> IncidentManager:
    """
    Resolve the shared application-scoped IncidentManager.
    """

    manager = container.incident_manager

    if manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Incident manager is not configured.",
        )

    return manager


# =============================================================================
# Detection Service
# =============================================================================


def get_detection_service(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> DetectionService:
    """
    Resolve the shared application-scoped DetectionService.
    """

    service = container.detection_service

    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection service is not configured.",
        )

    return service


# =============================================================================
# Detection Engine
# =============================================================================


def get_detection_engine(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> DetectionEngine:
    """
    Resolve the shared application-scoped DetectionEngine.
    """

    engine = container.detection_engine

    if engine is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection engine is not configured.",
        )

    return engine


# =============================================================================
# Optional Detection Service
# =============================================================================


def get_optional_detection_service(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> DetectionService | None:
    """
    Resolve DetectionService without converting absence into HTTP 503.
    """

    return container.detection_service


# =============================================================================
# Optional Detection Engine
# =============================================================================


def get_optional_detection_engine(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> DetectionEngine | None:
    """
    Resolve DetectionEngine without converting absence into HTTP 503.
    """

    return container.detection_engine


# =============================================================================
# Threat Intelligence Runtime
# =============================================================================


def get_threat_intelligence_runtime(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> ThreatIntelligenceService:
    """
    Resolve shared Threat Intelligence runtime.
    """

    service = container.threat_intelligence

    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Threat Intelligence runtime "
                "is not configured."
            ),
        )

    return service


# =============================================================================
# Threat Intelligence Request Service
# =============================================================================


def get_threat_intelligence(
    runtime: ThreatIntelligenceService = Depends(
        get_threat_intelligence_runtime,
    ),
    repository: IOCRepository = Depends(
        get_ioc_repository,
    ),
) -> ThreatIntelligenceService:
    """
    Resolve request-scoped Threat Intelligence service.

    Runtime components are reused while persistence is request-scoped.
    """

    return ThreatIntelligenceService(
        manager=runtime._manager,
        enricher=runtime._enricher,
        cache=runtime._cache,
        repository=repository,
    )


get_threat_intelligence_service = (
    get_threat_intelligence
)


# =============================================================================
# Request Metadata
# =============================================================================


def _request_id(
    request: Request,
) -> str | None:
    """
    Resolve request correlation ID.

    Preference:

        request.state.request_id
            ↓
        X-Request-ID
    """

    value = getattr(
        request.state,
        "request_id",
        None,
    )

    if value is None:
        value = request.headers.get(
            "X-Request-ID",
        )

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    return value[
        :MAX_REQUEST_ID_LENGTH
    ]


def _source_ip(
    request: Request,
) -> str | None:
    """
    Resolve direct client address.

    X-Forwarded-For is intentionally not trusted here.
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

    host = str(host).strip()

    if not host:
        return None

    return host[
        :MAX_SOURCE_IP_LENGTH
    ]


def _user_agent(
    request: Request,
) -> str | None:
    """Resolve User-Agent header."""

    value = request.headers.get(
        "User-Agent",
    )

    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    return value[
        :MAX_USER_AGENT_LENGTH
    ]


# =============================================================================
# Audit Metadata Security
# =============================================================================


_SENSITIVE_AUDIT_KEYS: frozenset[str] = frozenset(
    {
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
        "encryption_key_value",
        "encryptionkeyvalue",
        "signing_key",
        "signingkey",
        "signing_key_value",
        "signingkeyvalue",
        "authorization",
        "authorization_header",
        "authorizationheader",
        "auth_header",
        "authheader",
        "cookie",
        "cookies",
        "set_cookie",
        "setcookie",
        "credential",
        "credentials",
        "credential_material",
        "credentialmaterial",
        "credential_value",
        "credentialvalue",
        "session_secret",
        "sessionsecret",
        "session_secret_value",
        "sessionsecretvalue",
    }
)


_SENSITIVE_AUDIT_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwordhash",
    "hashedpassword",
    "hashpassword",
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
    "encryptionkeyvalue",
    "signingkey",
    "signingkeyvalue",
    "authorizationheader",
    "authheader",
    "credentialmaterial",
    "credentialvalue",
    "sessionsecret",
    "sessionsecretvalue",
)


def _normalize_audit_key(
    key: object,
) -> str:
    """Normalize an audit metadata key."""

    normalized = str(
        key,
    ).strip().lower()

    for separator in (
        "-",
        " ",
        ".",
        "/",
        "\\",
    ):
        normalized = normalized.replace(
            separator,
            "_",
        )

    while "__" in normalized:
        normalized = normalized.replace(
            "__",
            "_",
        )

    return normalized


def _is_sensitive_audit_key(
    key: object,
) -> bool:
    """Return True when a metadata key contains credential material."""

    normalized = _normalize_audit_key(
        key,
    )

    if normalized in _SENSITIVE_AUDIT_KEYS:
        return True

    compact = normalized.replace(
        "_",
        "",
    )

    return any(
        fragment in compact
        for fragment in _SENSITIVE_AUDIT_FRAGMENTS
    )


def _sanitize_audit_metadata(
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    """Remove known credential fields from audit metadata."""

    if not metadata:
        return {}

    sanitized: dict[str, Any] = {}

    for key, value in metadata.items():
        if _is_sensitive_audit_key(
            key,
        ):
            continue

        sanitized[str(key)] = value

    return sanitized


# =============================================================================
# Authentication Audit Compatibility Sink
# =============================================================================


class _AuditServiceAuthenticationSink:
    """
    Compatibility adapter for legacy AuthenticationService audit APIs.
    """

    def __init__(
        self,
        manager: PostgresSessionManager,
    ) -> None:
        self._manager = manager

    @staticmethod
    def _convert_record(
        record: AuditRecord,
    ) -> AuditCreate:
        """Convert legacy AuditRecord into canonical AuditCreate."""

        action = getattr(
            record,
            "action",
            None,
        )

        outcome = getattr(
            record,
            "outcome",
            None,
        )

        actor_user_id = getattr(
            record,
            "actor_user_id",
            None,
        )

        target_user_id = getattr(
            record,
            "target_user_id",
            None,
        )

        session_id = getattr(
            record,
            "session_id",
            None,
        )

        request_id = getattr(
            record,
            "request_id",
            None,
        )

        source_ip = getattr(
            record,
            "source_ip",
            None,
        )

        metadata = getattr(
            record,
            "metadata",
            None,
        )

        if isinstance(
            metadata,
            dict,
        ):
            metadata = _sanitize_audit_metadata(
                metadata,
            )
        else:
            metadata = {}

        return AuditCreate(
            action=str(
                action
                or "authentication.event",
            ),
            outcome=str(
                outcome
                or "failure",
            ),
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            session_id=session_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata_json=(
                metadata
                if metadata
                else None
            ),
        )

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """Persist authentication audit independently."""

        if not isinstance(
            record,
            AuditRecord,
        ):
            raise TypeError(
                "record must be an AuditRecord instance.",
            )

        audit = self._convert_record(
            record,
        )

        async with self._manager.session() as session:
            service = AuditService(
                session,
            )

            await service.log(
                audit,
            )

            await session.commit()


# =============================================================================
# Authentication Service Builder
# =============================================================================


def _build_authentication_service(
    *,
    session: AsyncSession,
    container: APIContainer,
) -> AuthenticationService:
    """Construct a request-scoped AuthenticationService."""

    if container.token_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authentication token service "
                "is not configured."
            ),
        )

    if container.password_hasher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authentication password service "
                "is not configured."
            ),
        )

    if container.role_registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authentication role registry "
                "is not configured."
            ),
        )

    from app.auth.adapters import (
        PostgresSessionRepository,
        PostgresUserRepository,
    )

    users = PostgresUserRepository(
        session,
    )

    sessions = PostgresSessionRepository(
        session,
    )

    audit_sink: Any | None = None

    if container.postgres_session_manager is not None:
        audit_sink = _AuditServiceAuthenticationSink(
            container.postgres_session_manager,
        )

    elif container.audit_sink is not None:
        audit_sink = container.audit_sink

    return AuthenticationService(
        users=users,
        tokens=container.token_service,
        sessions=sessions,
        password_hasher=container.password_hasher,
        audit=audit_sink,
        failure_audit=audit_sink,
        roles=container.role_registry,
        session_ttl=container.auth_session_ttl,
    )


# =============================================================================
# Authentication Service Dependency
# =============================================================================


def get_authentication_service(
    session: AsyncSession = Depends(
        get_db_session,
    ),
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> AuthenticationService:
    """Resolve request-scoped AuthenticationService."""

    if container.postgres_session_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authentication storage "
                "is not configured."
            ),
        )

    return _build_authentication_service(
        session=session,
        container=container,
    )


# =============================================================================
# Canonical AuditService
# =============================================================================


def get_audit_service(
    session: AsyncSession = Depends(
        get_db_session,
    ),
) -> AuditService:
    """Resolve canonical request-scoped AuditService."""

    return AuditService(
        session,
    )


# =============================================================================
# User Management Service Builder
# =============================================================================


def _build_user_management_service(
    *,
    session: AsyncSession,
    container: APIContainer,
    audit_service: AuditService,
) -> UserManagementService:
    """Construct request-scoped UserManagementService."""

    if container.password_hasher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authentication password service "
                "is not configured."
            ),
        )

    if container.role_registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authentication role registry "
                "is not configured."
            ),
        )

    from app.auth.adapters import (
        PostgresSessionRepository,
        PostgresUserRepository,
    )

    users = PostgresUserRepository(
        session,
    )

    sessions = PostgresSessionRepository(
        session,
    )

    return UserManagementService(
        users=users,
        sessions=sessions,
        audit=audit_service,
        password_hasher=container.password_hasher,
        roles=container.role_registry,
    )


# =============================================================================
# User Management Service Dependency
# =============================================================================


def get_user_management_service(
    session: AsyncSession = Depends(
        get_db_session,
    ),
    container: APIContainer = Depends(
        get_api_container,
    ),
    audit_service: AuditService = Depends(
        get_audit_service,
    ),
) -> UserManagementService:
    """Resolve request-scoped UserManagementService."""

    if container.postgres_session_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "User management storage "
                "is not configured."
            ),
        )

    return _build_user_management_service(
        session=session,
        container=container,
        audit_service=audit_service,
    )


# =============================================================================
# Authorization Service
# =============================================================================


def get_authorization_service(
    container: APIContainer = Depends(
        get_api_container,
    ),
) -> AuthorizationService:
    """Resolve centralized AuthorizationService."""

    authorization = (
        container.authorization_service
    )

    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authorization service "
                "is not configured."
            ),
        )

    return authorization


# =============================================================================
# Bearer Token
# =============================================================================


def get_bearer_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme,
    ),
) -> str:
    """Extract and validate a Bearer token."""

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


# =============================================================================
# Current Principal
# =============================================================================


async def get_current_principal(
    token: str = Depends(
        get_bearer_token,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> UserPrincipal:
    """Resolve the current authenticated principal."""

    try:
        principal = (
            await authentication.authenticate_token(
                token,
            )
        )

    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from None

    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return principal


# =============================================================================
# Required Authentication
# =============================================================================


async def require_authenticated_user(
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
) -> UserPrincipal:
    """Require an authenticated principal."""

    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return principal


# =============================================================================
# Authorization Audit
# =============================================================================


async def _record_authorization_audit(
    *,
    request: Request,
    manager: PostgresSessionManager | None,
    action: str,
    principal: UserPrincipal | None,
    metadata: dict[str, Any],
) -> bool:
    """Persist a security-critical authorization audit event."""

    if manager is None:
        logger.error(
            "Authorization audit storage is unavailable.",
            extra={
                "action": action,
                "request_id": _request_id(request),
            },
        )

        return False

    actor_user_id: UUID | None = None

    if principal is not None:
        candidate = getattr(
            principal,
            "user_id",
            None,
        )

        if isinstance(
            candidate,
            UUID,
        ):
            actor_user_id = candidate

    safe_metadata = _sanitize_audit_metadata(
        metadata,
    )

    user_agent = _user_agent(
        request,
    )

    if user_agent is not None:
        safe_metadata["user_agent"] = user_agent

    audit = AuditCreate(
        action=action,
        outcome="denied",
        actor_user_id=actor_user_id,
        target_user_id=None,
        session_id=None,
        request_id=_request_id(request),
        source_ip=_source_ip(request),
        metadata_json=(
            safe_metadata
            if safe_metadata
            else None
        ),
    )

    try:
        async with manager.session() as audit_session:
            audit_service = AuditService(
                audit_session,
            )

            await audit_service.log(
                audit,
            )

            await audit_session.commit()

        return True

    except (
        AuditValidationError,
        AuditServiceError,
    ):
        logger.exception(
            "Authorization audit persistence failed.",
            extra={
                "action": action,
                "actor_user_id": (
                    str(actor_user_id)
                    if actor_user_id is not None
                    else None
                ),
                "request_id": _request_id(request),
            },
        )

        return False

    except Exception:
        logger.exception(
            "Unexpected authorization audit persistence failure.",
            extra={
                "action": action,
                "actor_user_id": (
                    str(actor_user_id)
                    if actor_user_id is not None
                    else None
                ),
                "request_id": _request_id(request),
            },
        )

        return False


# =============================================================================
# Permission Dependency Factory
# =============================================================================


def require_permission(
    permission: str | Permission,
):
    """
    Create a dependency requiring one canonical SentinelSIEM permission.

    The supplied permission must exist in the canonical Permission enum.
    """

    if isinstance(
        permission,
        Permission,
    ):
        normalized_permission = permission.value

    elif isinstance(
        permission,
        str,
    ):
        normalized_permission = permission.strip().lower()

        if not normalized_permission:
            raise ValueError(
                "Permission name cannot be empty.",
            )

        try:
            normalized_permission = Permission(
                normalized_permission,
            ).value

        except ValueError as exc:
            raise ValueError(
                "Unknown SentinelSIEM permission: "
                f"{normalized_permission!r}",
            ) from exc

    else:
        raise TypeError(
            "Permission must be a Permission or string value.",
        )

    async def dependency(
        request: Request,
        principal: UserPrincipal = Depends(
            get_current_principal,
        ),
        authorization: AuthorizationService = Depends(
            get_authorization_service,
        ),
        container: APIContainer = Depends(
            get_api_container,
        ),
    ) -> UserPrincipal:
        """Enforce the canonical permission."""

        try:
            return authorization.require_permission(
                principal,
                normalized_permission,
            )

        except PermissionDenied as exc:
            await _record_authorization_audit(
                request=request,
                manager=container.postgres_session_manager,
                action="authorization.permission_denied",
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

    dependency.__permission__ = normalized_permission

    return dependency


# =============================================================================
# Role Dependency Factory
# =============================================================================


def require_role(
    role: str | Role,
):
    """
    Create a dependency requiring one canonical SentinelSIEM role.
    """

    if isinstance(
        role,
        Role,
    ):
        normalized_role = role.value

    elif isinstance(
        role,
        str,
    ):
        normalized_role = role.strip().upper()

        if not normalized_role:
            raise ValueError(
                "Role name cannot be empty.",
            )

        try:
            normalized_role = Role(
                normalized_role,
            ).value

        except ValueError as exc:
            raise ValueError(
                "Unknown SentinelSIEM role: "
                f"{normalized_role!r}",
            ) from exc

    else:
        raise TypeError(
            "Role must be a Role or string value.",
        )

    async def dependency(
        request: Request,
        principal: UserPrincipal = Depends(
            get_current_principal,
        ),
        authorization: AuthorizationService = Depends(
            get_authorization_service,
        ),
        container: APIContainer = Depends(
            get_api_container,
        ),
    ) -> UserPrincipal:
        """Enforce the canonical role."""

        try:
            return authorization.require_role(
                principal,
                normalized_role,
            )

        except PermissionDenied as exc:
            await _record_authorization_audit(
                request=request,
                manager=container.postgres_session_manager,
                action="authorization.role_denied",
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

    dependency.__role__ = normalized_role

    return dependency


# =============================================================================
# Asset Authorization Dependencies
# =============================================================================

# Locked SentinelSIEM Asset RBAC:
#
#     ASSETS_READ
#         → View Asset Inventory
#         → View Asset Details
#
#     ASSETS_MANAGE
#         → Create Asset
#         → Edit Asset
#         → Enable Asset
#         → Disable Asset
#
# No Asset Delete permission exists.

require_assets_read = require_permission(
    Permission.ASSETS_READ,
)

require_assets_manage = require_permission(
    Permission.ASSETS_MANAGE,
)


require_mitre_read = require_permission(
    Permission.MITRE_READ,
)


# =============================================================================
# MITRE Authorization Dependencies
# =============================================================================

# Locked MITRE RBAC:
#
#     ADMIN
#     SECURITY_ANALYST
#     SOC_ANALYST
#     INVESTIGATOR
#     VIEWER
#
# All five roles have:
#
#     MITRE_READ
#
# There is intentionally NO MITRE_MANAGE permission.
#
# MITRE ATT&CK knowledge is read-only through the API.
#
# Dataset updates happen through:
#
#     enterprise-attack.json
#             ↓
#        siem mitre import
#             ↓
#          PostgreSQL
#
# Detection → MITRE mapping management is a separate SentinelSIEM
# capability and is not represented by a MITRE knowledge permission.



# =============================================================================
# Optional Authentication
# =============================================================================


async def get_optional_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> UserPrincipal | None:
    """
    Resolve an optional authenticated principal.

    No credentials:
        → None

    Invalid credentials:
        → HTTP 401
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
        principal = (
            await authentication.authenticate_token(
                token,
            )
        )

    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from None

    return principal


# =============================================================================
# Public API
# =============================================================================


__all__ = [
    # -------------------------------------------------------------------------
    # Container
    # -------------------------------------------------------------------------

    "APIContainer",
    "get_api_container",

    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------

    "bearer_scheme",
    "get_bearer_token",
    "get_current_principal",
    "get_optional_principal",
    "require_authenticated_user",
    "get_authentication_service",

    # -------------------------------------------------------------------------
    # Authorization
    # -------------------------------------------------------------------------

    "get_authorization_service",
    "require_permission",
    "require_role",

    # -------------------------------------------------------------------------
    # Asset authorization
    # -------------------------------------------------------------------------

    "require_assets_read",
    "require_assets_manage",

    # -------------------------------------------------------------------------
    # MITRE authorization
    # -------------------------------------------------------------------------

    "require_mitre_read",

    # -------------------------------------------------------------------------
    # PostgreSQL
    # -------------------------------------------------------------------------

    "get_postgres_session_manager",
    "get_db_session",

    # -------------------------------------------------------------------------
    # Assets
    # -------------------------------------------------------------------------

    "get_asset_repository",
    "get_asset_service",

    # -------------------------------------------------------------------------
    # IOC
    # -------------------------------------------------------------------------

    "get_ioc_repository",

    # -------------------------------------------------------------------------
    # Audit
    # -------------------------------------------------------------------------

    "get_audit_service",

    # -------------------------------------------------------------------------
    # User Management
    # -------------------------------------------------------------------------

    "get_user_management_service",

    # -------------------------------------------------------------------------
    # Threat Intelligence
    # -------------------------------------------------------------------------

    "get_threat_intelligence_runtime",
    "get_threat_intelligence",
    "get_threat_intelligence_service",

    # -------------------------------------------------------------------------
    # MITRE
    # -------------------------------------------------------------------------

    "get_mitre_repository",
    "get_mitre_service",

    # -------------------------------------------------------------------------
    # OpenSearch repositories
    # -------------------------------------------------------------------------

    "get_alert_repository",
    "get_detection_repository",
    "get_incident_repository",

    # -------------------------------------------------------------------------
    # Alert
    # -------------------------------------------------------------------------

    "get_alert_manager",
    "get_alert_service",

    # -------------------------------------------------------------------------
    # Incident
    # -------------------------------------------------------------------------

    "get_incident_manager",

    # -------------------------------------------------------------------------
    # Detection
    # -------------------------------------------------------------------------

    "get_detection_service",
    "get_detection_engine",
    "get_optional_detection_service",
    "get_optional_detection_engine",

    # -------------------------------------------------------------------------
    # Realtime
    # -------------------------------------------------------------------------

    "get_websocket_publisher",
]