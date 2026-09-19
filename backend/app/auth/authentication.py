from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from .audit import AuditSink
from .models import (
    AuditAction,
    AuditOutcome,
    AuditRecord,
    SessionRecord,
    UserPrincipal,
)
from .password import PasswordHasher
from .repositories import (
    AuthAuditRepository,
    AuthenticationRepositoryError,
    SessionRepository,
    UserRepository,
)
from .roles import RoleRegistry
from .tokens import TokenError, TokenService

logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

DEFAULT_SESSION_TTL = timedelta(minutes=30)
DEFAULT_MAX_FAILED_LOGIN_ATTEMPTS = 5

PENDING_TOKEN_PREFIX = "pending:"

MAX_LOGIN_LENGTH = 320
MAX_PASSWORD_LENGTH = 1024
MAX_REQUEST_ID_LENGTH = 128
MAX_IP_ADDRESS_LENGTH = 128
MAX_USER_AGENT_LENGTH = 512


# ============================================================================
# Errors
# ============================================================================


class AuthenticationError(ValueError):
    """
    Generic public-facing authentication/security failure.

    Public callers must not be able to distinguish between:

        - unknown user
        - invalid password
        - inactive account
        - locked account
        - automatic lockout
        - invalid token
        - invalid session
        - repository failure
        - internal authentication failure
    """

    pass


# ============================================================================
# Result DTOs
# ============================================================================


@dataclass(frozen=True, slots=True)
class LoginResult:
    """
    Successful authentication result.

    access_token:
        Newly issued JWT access token.

    principal:
        Authenticated request principal.
    """

    access_token: str
    principal: UserPrincipal


# ============================================================================
# Authentication Service
# ============================================================================


class AuthenticationService:
    """
    SentinelSIEM authentication service.

    Responsibilities
    ----------------

    Authentication:

        - login normalization
        - password verification
        - failed-login tracking
        - automatic account lockout
        - successful-login state tracking
        - server-side session creation
        - JWT issuance
        - JWT/session binding
        - JWT/session validation

    Authorization:

        - current user state
        - current RBAC state
        - principal construction

    Session lifecycle:

        - active-session lookup
        - active-session listing
        - logout
        - revoke all sessions
        - orphan-session cleanup

    Audit:

        - login success
        - login failure
        - token validation failure
        - logout
        - session revocation

    Security model
    --------------

    Passwords, password hashes, JWTs, JTIs and secrets must never be written
    to audit metadata or normal application logs.

    Transaction ownership
    ---------------------

    The caller owns the database transaction.

    Repository implementations never commit independently.
    """

    def __init__(
        self,
        *,
        users: UserRepository,
        tokens: TokenService,
        sessions: SessionRepository,
        password_hasher: PasswordHasher,
        audit: AuditSink | AuthAuditRepository,
        roles: RoleRegistry | None = None,
        session_ttl: timedelta = DEFAULT_SESSION_TTL,
        failure_audit: AuditSink | AuthAuditRepository | None = None,
        max_failed_login_attempts: int = (DEFAULT_MAX_FAILED_LOGIN_ATTEMPTS),
    ) -> None:
        if session_ttl <= timedelta(0):
            raise ValueError("Session TTL must be positive.")

        if max_failed_login_attempts < 1:
            raise ValueError("Maximum failed login attempts must be at least 1.")

        if not isinstance(max_failed_login_attempts, int):
            raise ValueError("Maximum failed login attempts must be an integer.")

        self._users = users
        self._tokens = tokens
        self._sessions = sessions
        self._passwords = password_hasher

        self._audit = audit
        self._failure_audit = failure_audit if failure_audit is not None else audit

        self._roles = roles or RoleRegistry()

        self._session_ttl = session_ttl
        self._max_failed_login_attempts = max_failed_login_attempts

    # ========================================================================
    # Time helpers
    # ========================================================================

    @staticmethod
    def _utc_now() -> datetime:
        """
        Return the current timezone-aware UTC timestamp.
        """
        return datetime.now(UTC)

    # ========================================================================
    # Input validation / normalization
    # ========================================================================

    @staticmethod
    def _normalize_login(login: str) -> str:
        """
        Normalize username/email lookup input.

        Only surrounding whitespace and case are normalized.

        Passwords are deliberately never processed here.
        """

        if not isinstance(login, str):
            raise ValueError("Login identifier must be a string.")

        normalized = login.strip().lower()

        if not normalized:
            raise ValueError("Login identifier must not be empty.")

        if len(normalized) > MAX_LOGIN_LENGTH:
            raise ValueError("Login identifier is too long.")

        return normalized

    @staticmethod
    def _validate_password(password: str) -> str:
        """
        Validate password input without modifying it.

        Passwords are never:

            - stripped
            - lowercased
            - uppercased
            - normalized
        """

        if not isinstance(password, str):
            raise ValueError("Password must be a string.")

        if not password:
            raise ValueError("Password must not be empty.")

        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError("Password is too long.")

        return password

    @staticmethod
    def _validate_uuid(
        value: UUID,
        *,
        field_name: str,
    ) -> UUID:
        """
        Validate UUID arguments defensively.
        """

        if not isinstance(value, UUID):
            raise ValueError(f"{field_name} must be a UUID.")

        return value

    @staticmethod
    def _normalize_request_id(
        request_id: str | None,
    ) -> str | None:
        """
        Normalize bounded request correlation metadata.
        """

        if request_id is None:
            return None

        if not isinstance(request_id, str):
            return None

        value = request_id.strip()

        if not value:
            return None

        return value[:MAX_REQUEST_ID_LENGTH]

    @staticmethod
    def _normalize_ip(
        ip_address: str | None,
    ) -> str | None:
        """
        Normalize bounded source IP metadata.

        Proxy trust is intentionally outside this service.
        """

        if ip_address is None:
            return None

        if not isinstance(ip_address, str):
            return None

        value = ip_address.strip()

        if not value:
            return None

        return value[:MAX_IP_ADDRESS_LENGTH]

    @staticmethod
    def _normalize_user_agent(
        user_agent: str | None,
    ) -> str | None:
        """
        Normalize bounded User-Agent metadata.
        """

        if user_agent is None:
            return None

        if not isinstance(user_agent, str):
            return None

        value = user_agent.strip()

        if not value:
            return None

        return value[:MAX_USER_AGENT_LENGTH]

    # ========================================================================
    # Audit helpers
    # ========================================================================

    @staticmethod
    async def _write_audit(
        sink: AuditSink | AuthAuditRepository,
        record: AuditRecord,
    ) -> None:
        """
        Support both synchronous AuditSink implementations and asynchronous
        repository implementations.
        """

        result = sink.record(record)

        if inspect.isawaitable(result):
            await result

    async def _audit_record(
        self,
        record: AuditRecord,
    ) -> None:
        """
        Persist a normal authentication audit record.

        Errors intentionally propagate.
        """

        await self._write_audit(
            self._audit,
            record,
        )

    async def _audit_login_failure(
        self,
        *,
        request_id: str | None,
        ip_address: str | None,
        reason: str = "invalid_credentials",
    ) -> None:
        """
        Persist a failed authentication audit event.

        Failed authentication auditing is best-effort from the caller's
        perspective so that an audit outage does not expose internal details.

        Never include:

            - login identifier
            - email
            - password
            - password hash
            - JWT
            - JTI
            - API key
            - secret
        """

        record = AuditRecord(
            action=AuditAction.LOGIN_FAILURE,
            outcome=AuditOutcome.FAILURE,
            request_id=self._normalize_request_id(request_id),
            source_ip=self._normalize_ip(ip_address),
            metadata={
                "reason": reason,
            },
        )

        try:
            await self._write_audit(
                self._failure_audit,
                record,
            )

        except Exception:
            logger.exception(
                "Unable to persist failed authentication audit event.",
                extra={
                    "request_id": self._normalize_request_id(request_id),
                    "source_ip": self._normalize_ip(ip_address),
                    "reason": reason,
                },
            )

    async def _audit_token_failure(
        self,
        *,
        request_id: str | None,
        reason: str = "invalid_token_or_session",
    ) -> None:
        """
        Persist a token authentication failure.

        Token-validation failures use the canonical
        LOGIN_FAILURE audit action so authentication failures
        remain consistent across credential and token paths.

        No token material, JWT, JTI, claims, or secrets are
        written to audit metadata.
        """

        record = AuditRecord(
            action=AuditAction.LOGIN_FAILURE,
            outcome=AuditOutcome.FAILURE,
            request_id=self._normalize_request_id(request_id),
            metadata={
                "reason": reason,
            },
        )

        try:
            await self._write_audit(
                self._failure_audit,
                record,
            )
        except Exception:
            logger.exception(
                "Unable to persist token authentication failure audit event.",
                extra={
                    "request_id": request_id,
                    "reason": reason,
                },
            )

    async def _safe_audit(
        self,
        record: AuditRecord,
        *,
        event_name: str,
    ) -> None:
        """
        Best-effort audit helper for already-completed security operations.

        An audit failure must never cause a successful login/logout/session
        revocation to be reported as unsuccessful after the security action
        has already completed.
        """

        try:
            await self._audit_record(record)

        except Exception:
            logger.exception(
                "Unable to persist authentication audit event.",
                extra={
                    "event": event_name,
                    "request_id": record.request_id,
                },
            )

    # ========================================================================
    # Failed-login state
    # ========================================================================

    async def _record_failed_login(
        self,
        *,
        user_id: UUID,
        request_id: str | None,
        ip_address: str | None,
    ) -> None:
        """
        Atomically record a failed authentication attempt.

        The repository performs the actual database state transition:

            failed_login_count += 1

        and locks the account when the configured threshold is reached.
        """

        try:
            updated_user = await self._users.record_failed_login(
                user_id,
                max_attempts=self._max_failed_login_attempts,
            )

        except AuthenticationRepositoryError:
            logger.exception(
                "Unable to update failed-login security state.",
                extra={
                    "user_id": str(user_id),
                    "request_id": self._normalize_request_id(request_id),
                    "source_ip": self._normalize_ip(ip_address),
                },
            )

            await self._audit_login_failure(
                request_id=request_id,
                ip_address=ip_address,
                reason="failed_login_state_update_error",
            )

            raise AuthenticationError("Authentication service unavailable.") from None

        except Exception:
            logger.exception(
                "Unexpected failed-login state failure.",
                extra={
                    "user_id": str(user_id),
                    "request_id": self._normalize_request_id(request_id),
                    "source_ip": self._normalize_ip(ip_address),
                },
            )

            await self._audit_login_failure(
                request_id=request_id,
                ip_address=ip_address,
                reason="failed_login_state_update_error",
            )

            raise AuthenticationError("Authentication service unavailable.") from None

        if updated_user is None:
            await self._audit_login_failure(
                request_id=request_id,
                ip_address=ip_address,
                reason="invalid_credentials",
            )
            return

        if updated_user.is_locked:
            await self._audit_login_failure(
                request_id=request_id,
                ip_address=ip_address,
                reason="account_locked_after_failed_logins",
            )
            return

        await self._audit_login_failure(
            request_id=request_id,
            ip_address=ip_address,
            reason="invalid_credentials",
        )

    # ========================================================================
    # Successful-login state
    # ========================================================================

    async def _record_successful_login(
        self,
        *,
        user_id: UUID,
        request_id: str | None,
        ip_address: str | None,
    ) -> None:
        """
        Atomically record successful authentication.

        Repository responsibilities:

            failed_login_count = 0
            last_login_at = current UTC timestamp
            updated_at = current UTC timestamp

        The repository must not unlock an administrative account lock.
        """

        try:
            updated_user = await self._users.record_successful_login(
                user_id,
            )

        except AuthenticationRepositoryError:
            logger.exception(
                "Unable to update successful-login state.",
                extra={
                    "user_id": str(user_id),
                    "request_id": self._normalize_request_id(request_id),
                    "source_ip": self._normalize_ip(ip_address),
                },
            )

            raise AuthenticationRepositoryError(
                "Unable to update successful login state."
            ) from None

        except Exception:
            logger.exception(
                "Unexpected successful-login state failure.",
                extra={
                    "user_id": str(user_id),
                    "request_id": self._normalize_request_id(request_id),
                    "source_ip": self._normalize_ip(ip_address),
                },
            )

            raise AuthenticationRepositoryError(
                "Unable to update successful login state."
            ) from None

        if updated_user is None:
            raise AuthenticationRepositoryError("Unable to update successful login state.")

    # ========================================================================
    # Principal construction
    # ========================================================================

    def _build_principal(
        self,
        *,
        user: Any,
        session_id: UUID,
    ) -> UserPrincipal:
        """
        Build the authenticated principal.

        Authorization permissions are always resolved from the current
        RoleRegistry.

        JWT permission claims are never trusted.
        """

        permissions = self._roles.permissions_for(
            user.roles,
        )

        return UserPrincipal(
            user_id=user.user_id,
            username=user.username,
            roles=frozenset(str(role) for role in user.roles),
            permissions=frozenset(str(permission) for permission in permissions),
            session_id=session_id,
        )

    # ========================================================================
    # Login
    # ========================================================================

    async def login(
        self,
        *,
        login: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> LoginResult:
        """
        Authenticate credentials and create a JWT-backed server session.

        Security guarantees:

            - generic public authentication failures
            - normalized login identifier
            - password is never modified
            - inactive accounts are rejected
            - locked accounts are rejected
            - invalid passwords update failed-login state
            - automatic lockout is repository-atomic
            - successful authentication resets failed-login state
            - successful authentication updates last_login_at
            - JWT is bound to a server-side session
            - JWT JTI is bound to that session
            - current RBAC permissions are used
            - audit records contain no credentials
        """

        # --------------------------------------------------------------------
        # Validate inputs
        # --------------------------------------------------------------------

        try:
            normalized_login = self._normalize_login(login)

            validated_password = self._validate_password(password)

        except ValueError:
            await self._audit_login_failure(
                request_id=request_id,
                ip_address=ip_address,
                reason="invalid_credentials",
            )

            raise AuthenticationError("Invalid credentials.") from None

        normalized_ip = self._normalize_ip(ip_address)

        normalized_user_agent = self._normalize_user_agent(user_agent)

        normalized_request_id = self._normalize_request_id(request_id)

        # --------------------------------------------------------------------
        # Lookup user
        # --------------------------------------------------------------------

        try:
            user = await self._users.get_by_login(
                normalized_login,
            )

        except AuthenticationRepositoryError:
            await self._audit_login_failure(
                request_id=normalized_request_id,
                ip_address=normalized_ip,
                reason="authentication_repository_failure",
            )

            raise AuthenticationError("Authentication service unavailable.") from None

        except Exception:
            logger.exception(
                "Unexpected user repository failure during login.",
                extra={
                    "request_id": normalized_request_id,
                    "source_ip": normalized_ip,
                },
            )

            await self._audit_login_failure(
                request_id=normalized_request_id,
                ip_address=normalized_ip,
                reason="authentication_repository_failure",
            )

            raise AuthenticationError("Authentication service unavailable.") from None

        # --------------------------------------------------------------------
        # Account state
        # --------------------------------------------------------------------

        account_usable = user is not None and user.is_active and not user.is_locked

        # --------------------------------------------------------------------
        # Password verification
        # --------------------------------------------------------------------

        password_valid = False

        if user is not None:
            try:
                password_valid = bool(
                    self._passwords.verify(
                        validated_password,
                        user.password_hash,
                    )
                )

            except (TypeError, ValueError):
                password_valid = False

            except Exception:
                logger.exception(
                    "Unexpected password verification failure.",
                    extra={
                        "request_id": normalized_request_id,
                        "source_ip": normalized_ip,
                    },
                )

                password_valid = False

        # --------------------------------------------------------------------
        # Generic authentication failure
        # --------------------------------------------------------------------

        if not account_usable or not password_valid:
            if user is not None and user.is_active and not user.is_locked and not password_valid:
                await self._record_failed_login(
                    user_id=user.user_id,
                    request_id=normalized_request_id,
                    ip_address=normalized_ip,
                )

            else:
                await self._audit_login_failure(
                    request_id=normalized_request_id,
                    ip_address=normalized_ip,
                    reason="invalid_credentials",
                )

            raise AuthenticationError("Invalid credentials.")

        # --------------------------------------------------------------------
        # Successful authentication state
        # --------------------------------------------------------------------

        try:
            await self._record_successful_login(
                user_id=user.user_id,
                request_id=normalized_request_id,
                ip_address=normalized_ip,
            )

        except AuthenticationRepositoryError:
            await self._audit_login_failure(
                request_id=normalized_request_id,
                ip_address=normalized_ip,
                reason="authentication_repository_failure",
            )

            raise AuthenticationError("Authentication service unavailable.") from None

        # --------------------------------------------------------------------
        # Create server-side session
        # --------------------------------------------------------------------

        now = self._utc_now()
        session_id = uuid4()

        pending_token_id = f"{PENDING_TOKEN_PREFIX}{session_id}"

        session = SessionRecord(
            session_id=session_id,
            user_id=user.user_id,
            token_id=pending_token_id,
            created_at=now,
            expires_at=now + self._session_ttl,
            revoked_at=None,
            ip_address=normalized_ip,
            user_agent=normalized_user_agent,
        )

        try:
            session = await self._sessions.create(
                session,
            )

        except AuthenticationRepositoryError:
            await self._audit_login_failure(
                request_id=normalized_request_id,
                ip_address=normalized_ip,
                reason="session_creation_failure",
            )

            raise AuthenticationError("Authentication service unavailable.") from None

        except Exception:
            logger.exception(
                "Unexpected authentication session creation failure.",
                extra={
                    "user_id": str(user.user_id),
                    "session_id": str(session_id),
                    "request_id": normalized_request_id,
                },
            )

            await self._audit_login_failure(
                request_id=normalized_request_id,
                ip_address=normalized_ip,
                reason="session_creation_failure",
            )

            raise AuthenticationError("Authentication service unavailable.") from None

        # --------------------------------------------------------------------
        # Issue JWT and bind JTI
        # --------------------------------------------------------------------

        token: str | None = None

        try:
            token = self._tokens.issue(
                user.user_id,
                session.session_id,
            )

            claims = self._tokens.decode(
                token,
            )

            if claims.subject != user.user_id:
                raise TokenError("Issued token subject mismatch.")

            if claims.session_id != session.session_id:
                raise TokenError("Issued token session mismatch.")

            if not claims.token_id:
                raise TokenError("Issued token has no JTI.")

            if claims.expires_at <= claims.issued_at:
                raise TokenError("Issued token has invalid lifetime.")

            session = await self._sessions.bind_token(
                session.session_id,
                claims.token_id,
            )

            if session.user_id != user.user_id:
                raise TokenError("Bound session user mismatch.")

            if session.token_id != claims.token_id:
                raise TokenError("Bound session token mismatch.")

        except (
            AuthenticationRepositoryError,
            TokenError,
            ValueError,
        ):
            await self._revoke_orphaned_session(
                session=session,
                user_id=user.user_id,
                request_id=normalized_request_id,
            )

            await self._audit_login_failure(
                request_id=normalized_request_id,
                ip_address=normalized_ip,
                reason="token_or_session_binding_failure",
            )

            raise AuthenticationError("Authentication service unavailable.") from None

        except Exception:
            logger.exception(
                "Unexpected JWT issuance/binding failure.",
                extra={
                    "user_id": str(user.user_id),
                    "session_id": str(session.session_id),
                    "request_id": normalized_request_id,
                },
            )

            await self._revoke_orphaned_session(
                session=session,
                user_id=user.user_id,
                request_id=normalized_request_id,
            )

            await self._audit_login_failure(
                request_id=normalized_request_id,
                ip_address=normalized_ip,
                reason="token_or_session_binding_failure",
            )

            raise AuthenticationError("Authentication service unavailable.") from None

        if token is None:
            await self._revoke_orphaned_session(
                session=session,
                user_id=user.user_id,
                request_id=normalized_request_id,
            )

            raise AuthenticationError("Authentication service unavailable.")

        # --------------------------------------------------------------------
        # Build current principal
        # --------------------------------------------------------------------

        principal = self._build_principal(
            user=user,
            session_id=session.session_id,
        )

        # --------------------------------------------------------------------
        # Successful login audit
        # --------------------------------------------------------------------

        await self._safe_audit(
            AuditRecord(
                action=AuditAction.LOGIN_SUCCESS,
                outcome=AuditOutcome.SUCCESS,
                actor_user_id=user.user_id,
                session_id=session.session_id,
                request_id=normalized_request_id,
                source_ip=normalized_ip,
            ),
            event_name="login_success",
        )

        return LoginResult(
            access_token=token,
            principal=principal,
        )

    # ========================================================================
    # Orphan session cleanup
    # ========================================================================

    async def _revoke_orphaned_session(
        self,
        *,
        session: SessionRecord,
        user_id: UUID,
        request_id: str | None,
    ) -> None:
        """
        Best-effort revoke for sessions created before JWT issuance/binding
        completed.
        """

        try:
            await self._sessions.revoke(
                session.session_id,
            )

        except Exception:
            logger.exception(
                "Unable to revoke orphaned authentication session.",
                extra={
                    "user_id": str(user_id),
                    "session_id": str(session.session_id),
                    "request_id": request_id,
                },
            )

    # ========================================================================
    # Token authentication
    # ========================================================================

    async def authenticate_token(
        self,
        access_token: str,
        *,
        request_id: str | None = None,
    ) -> UserPrincipal:
        """
        Authenticate a JWT against current server-side security state.

        Validation sequence:

            1. basic token input
            2. JWT cryptographic validation
            3. algorithm validation
            4. issuer validation
            5. audience validation
            6. required claims
            7. expiration
            8. session existence
            9. session expiration
            10. session revocation
            11. JWT subject/session binding
            12. JWT JTI/session binding
            13. user existence
            14. active account state
            15. locked account state
            16. current RBAC resolution

        JWT permissions are never trusted.
        """

        normalized_request_id = self._normalize_request_id(request_id)

        # --------------------------------------------------------------------
        # Basic input validation
        # --------------------------------------------------------------------

        if not isinstance(access_token, str):
            await self._audit_token_failure(
                request_id=normalized_request_id,
                reason="invalid_token_input",
            )

            raise AuthenticationError("Authentication failed.")

        token = access_token.strip()

        if not token:
            await self._audit_token_failure(
                request_id=normalized_request_id,
                reason="invalid_token_input",
            )

            raise AuthenticationError("Authentication failed.")

        # --------------------------------------------------------------------
        # Decode and validate JWT
        # --------------------------------------------------------------------

        try:
            claims = self._tokens.decode(
                token,
            )

            # ---------------------------------------------------------------
            # Active server-side session
            # ---------------------------------------------------------------

            session = await self._sessions.get_active(
                claims.session_id,
            )

            if session is None:
                raise TokenError("Authentication session is not active.")

            # ---------------------------------------------------------------
            # Defensive session checks
            # ---------------------------------------------------------------

            now = self._utc_now()

            if session.revoked_at is not None:
                raise TokenError("Authentication session is revoked.")

            if session.expires_at <= now:
                raise TokenError("Authentication session is expired.")

            if session.user_id != claims.subject:
                raise TokenError("Token/session subject mismatch.")

            # ---------------------------------------------------------------
            # JTI/session binding
            # ---------------------------------------------------------------

            if not session.token_id:
                raise TokenError("Authentication session has no bound token.")

            if session.token_id.startswith(PENDING_TOKEN_PREFIX):
                raise TokenError("Authentication session token is not bound.")

            if session.token_id != claims.token_id:
                raise TokenError("Token/session identifier mismatch.")

            # ---------------------------------------------------------------
            # Current user state
            # ---------------------------------------------------------------

            user = await self._users.get_by_id(
                claims.subject,
            )

            if user is None:
                raise TokenError("Authenticated user does not exist.")

            if not user.is_active:
                raise TokenError("Authenticated user is inactive.")

            if user.is_locked:
                raise TokenError("Authenticated user is locked.")

            # ---------------------------------------------------------------
            # Current RBAC state
            # ---------------------------------------------------------------

            return self._build_principal(
                user=user,
                session_id=session.session_id,
            )

        except (
            TokenError,
            AuthenticationRepositoryError,
            ValueError,
        ):
            await self._audit_token_failure(
                request_id=normalized_request_id,
                reason="invalid_token_or_session",
            )

            raise AuthenticationError("Authentication failed.") from None

        except Exception:
            logger.exception(
                "Unexpected token authentication failure.",
                extra={
                    "request_id": normalized_request_id,
                },
            )

            await self._audit_token_failure(
                request_id=normalized_request_id,
                reason="authentication_internal_failure",
            )

            raise AuthenticationError("Authentication failed.") from None

    # ========================================================================
    # Active session listing
    # ========================================================================

    async def list_active_sessions(
        self,
        user_id: UUID,
    ) -> list[SessionRecord]:
        """
        Return only active sessions belonging to the requested user.

        The repository is expected to filter revoked/expired sessions.
        The service performs a second defensive validation.
        """

        self._validate_uuid(
            user_id,
            field_name="user_id",
        )

        try:
            sessions = await self._sessions.list_active_user_sessions(
                user_id,
            )

        except AuthenticationRepositoryError:
            logger.exception(
                "Unable to retrieve active authentication sessions.",
                extra={
                    "user_id": str(user_id),
                },
            )

            raise AuthenticationError("Unable to retrieve authentication sessions.") from None

        except Exception:
            logger.exception(
                "Unexpected active-session lookup failure.",
                extra={
                    "user_id": str(user_id),
                },
            )

            raise AuthenticationError("Unable to retrieve authentication sessions.") from None

        now = self._utc_now()

        validated: list[SessionRecord] = []

        for session in sessions:
            # ---------------------------------------------------------------
            # Cross-user defense
            # ---------------------------------------------------------------

            if session.user_id != user_id:
                logger.error(
                    "Session repository returned a cross-user session.",
                    extra={
                        "requested_user_id": str(user_id),
                        "returned_user_id": str(session.user_id),
                        "session_id": str(session.session_id),
                    },
                )
                continue

            # ---------------------------------------------------------------
            # Revocation defense
            # ---------------------------------------------------------------

            if session.revoked_at is not None:
                continue

            # ---------------------------------------------------------------
            # Expiration defense
            # ---------------------------------------------------------------

            if session.expires_at <= now:
                continue

            validated.append(session)

        return validated

    # ========================================================================
    # Logout
    # ========================================================================

    async def logout(
        self,
        principal: UserPrincipal,
        *,
        request_id: str | None = None,
        ip_address: str | None = None,
    ) -> bool:
        """
        Revoke the current authenticated session.

        Returns:

            True:
                Session was revoked.

            False:
                Session did not exist or was already revoked.
        """

        if not isinstance(principal, UserPrincipal):
            raise AuthenticationError("Invalid authentication principal.")

        normalized_request_id = self._normalize_request_id(request_id)

        normalized_ip = self._normalize_ip(ip_address)

        try:
            revoked = await self._sessions.revoke(
                principal.session_id,
            )

        except AuthenticationRepositoryError:
            await self._safe_audit(
                AuditRecord(
                    action=AuditAction.LOGOUT,
                    outcome=AuditOutcome.FAILURE,
                    actor_user_id=principal.user_id,
                    session_id=principal.session_id,
                    request_id=normalized_request_id,
                    source_ip=normalized_ip,
                    metadata={
                        "reason": "session_repository_failure",
                    },
                ),
                event_name="logout_failure",
            )

            raise AuthenticationError("Unable to complete logout.") from None

        except Exception:
            logger.exception(
                "Unexpected logout failure.",
                extra={
                    "user_id": str(principal.user_id),
                    "session_id": str(principal.session_id),
                    "request_id": normalized_request_id,
                },
            )

            await self._safe_audit(
                AuditRecord(
                    action=AuditAction.LOGOUT,
                    outcome=AuditOutcome.FAILURE,
                    actor_user_id=principal.user_id,
                    session_id=principal.session_id,
                    request_id=normalized_request_id,
                    source_ip=normalized_ip,
                    metadata={
                        "reason": "internal_failure",
                    },
                ),
                event_name="logout_internal_failure",
            )

            raise AuthenticationError("Unable to complete logout.") from None

        await self._safe_audit(
            AuditRecord(
                action=AuditAction.LOGOUT,
                outcome=(AuditOutcome.SUCCESS if revoked else AuditOutcome.FAILURE),
                actor_user_id=principal.user_id,
                session_id=principal.session_id,
                request_id=normalized_request_id,
                source_ip=normalized_ip,
                metadata=(
                    {}
                    if revoked
                    else {
                        "reason": "session_not_active",
                    }
                ),
            ),
            event_name="logout",
        )

        return revoked

    # ========================================================================
    # Revoke all sessions
    # ========================================================================

    async def revoke_all_sessions(
        self,
        user_id: UUID,
    ) -> int:
        """
        Revoke all currently active authentication sessions for a user.

        Typical callers:

            - password reset
            - account disable
            - account lock
            - administrative session revocation
            - security response
        """

        self._validate_uuid(
            user_id,
            field_name="user_id",
        )

        try:
            count = await self._sessions.revoke_user_sessions(
                user_id,
            )

        except AuthenticationRepositoryError:
            await self._safe_audit(
                AuditRecord(
                    action=AuditAction.SESSIONS_REVOKED,
                    outcome=AuditOutcome.FAILURE,
                    target_user_id=user_id,
                    metadata={
                        "reason": "session_repository_failure",
                    },
                ),
                event_name="sessions_revoked_failure",
            )

            raise AuthenticationError("Unable to revoke authentication sessions.") from None

        except Exception:
            logger.exception(
                "Unexpected session revocation failure.",
                extra={
                    "user_id": str(user_id),
                },
            )

            await self._safe_audit(
                AuditRecord(
                    action=AuditAction.SESSIONS_REVOKED,
                    outcome=AuditOutcome.FAILURE,
                    target_user_id=user_id,
                    metadata={
                        "reason": "internal_failure",
                    },
                ),
                event_name="sessions_revoked_internal_failure",
            )

            raise AuthenticationError("Unable to revoke authentication sessions.") from None

        await self._safe_audit(
            AuditRecord(
                action=AuditAction.SESSIONS_REVOKED,
                outcome=AuditOutcome.SUCCESS,
                target_user_id=user_id,
                metadata={
                    "count": count,
                },
            ),
            event_name="sessions_revoked",
        )

        return count


# ============================================================================
# Public exports
# ============================================================================

__all__ = [
    "AuthenticationError",
    "AuthenticationService",
    "LoginResult",
    "DEFAULT_MAX_FAILED_LOGIN_ATTEMPTS",
    "DEFAULT_SESSION_TTL",
]
