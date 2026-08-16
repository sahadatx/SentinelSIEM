from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from typing import Any
from uuid import UUID, uuid4

from .audit import AuditSink
from .models import AuditRecord, SessionRecord, UserPrincipal
from .password import PasswordHasher
from .repositories import (
    AuthenticationRepositoryError,
    AuthAuditRepository,
    SessionRepository,
    UserRepository,
)
from .roles import RoleRegistry
from .tokens import TokenError, TokenService


logger = logging.getLogger(__name__)


# ============================================================================
# Authentication errors
# ============================================================================


class AuthenticationError(ValueError):
    """
    Generic authentication failure.

    Authentication callers must not be able to distinguish:

    - unknown user
    - invalid password
    - inactive account
    - locked account
    - repository failure
    - invalid authentication state

    from the public authentication error.
    """


# ============================================================================
# Login result
# ============================================================================


@dataclass(frozen=True, slots=True)
class LoginResult:
    """
    Result returned after successful authentication.
    """

    access_token: str
    principal: UserPrincipal


# ============================================================================
# Authentication service
# ============================================================================


class AuthenticationService:
    """
    Coordinate:

    - credential verification
    - authentication sessions
    - JWT issuance
    - JWT/session validation
    - RBAC principal construction
    - authentication audit logging

    Persistence is accessed only through repository abstractions.

    IMPORTANT:

    ``audit`` is the normal request-scoped audit repository.

    ``failure_audit`` is an optional independent audit repository/sink used
    specifically for failed authentication events.

    This separation is required because an authentication failure normally
    results in HTTP 401, which causes the request-scoped database transaction
    to roll back.

    Failed-login security audit records therefore need their own transaction.
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
        session_ttl: timedelta = timedelta(minutes=30),
        failure_audit: AuditSink | AuthAuditRepository | None = None,
    ) -> None:
        """
        Initialize the authentication service.

        Parameters
        ----------
        users:
            Authentication user repository.

        tokens:
            JWT token service.

        sessions:
            Authentication session repository.

        password_hasher:
            Password hashing/verification service.

        audit:
            Normal request-scoped audit sink.

        roles:
            Role/permission registry.

        session_ttl:
            Authentication session lifetime.

        failure_audit:
            Independent audit sink for failed authentication attempts.

            When supplied, failed-login records are written through this
            adapter instead of the normal request-scoped audit transaction.
        """

        if session_ttl <= timedelta(0):
            raise ValueError(
                "Session TTL must be positive."
            )

        self._users = users
        self._tokens = tokens
        self._sessions = sessions
        self._passwords = password_hasher

        # Normal request-scoped audit.
        self._audit = audit

        # Dedicated durable failed-login audit.
        #
        # If no dedicated sink is supplied, preserve backward compatibility
        # by falling back to the normal audit sink.
        self._failure_audit = (
            failure_audit
            if failure_audit is not None
            else audit
        )

        self._roles = roles or RoleRegistry()
        self._session_ttl = session_ttl

    # ========================================================================
    # Generic audit helper
    # ========================================================================

    @staticmethod
    async def _write_audit(
        sink: AuditSink | AuthAuditRepository,
        record: AuditRecord,
    ) -> None:
        """
        Write one audit record.

        Supports both:

        - synchronous AuditSink implementations
        - asynchronous repository implementations

        The repository/sink itself owns persistence semantics.
        """

        result = sink.record(record)

        if hasattr(result, "__await__"):
            await result

    # ========================================================================
    # Normal audit
    # ========================================================================

    async def _audit_record(
        self,
        record: AuditRecord,
    ) -> None:
        """
        Write a normal authentication audit event.

        This uses the request-scoped audit sink.
        """

        await self._write_audit(
            self._audit,
            record,
        )

    # ========================================================================
    # Failed-login audit
    # ========================================================================

    async def _audit_login_failure(
        self,
        *,
        request_id: str | None,
        ip_address: str | None,
        reason: str = "invalid_credentials",
    ) -> None:
        """
        Persist a failed authentication audit event.

        SECURITY REQUIREMENT
        -------------------

        This method intentionally uses ``self._failure_audit`` rather than
        ``self._audit``.

        In the production PostgreSQL API wiring, ``self._failure_audit`` is
        backed by an independent database transaction.

        Therefore:

            login failure
                -> audit COMMIT
                -> AuthenticationError
                -> HTTP 401
                -> request transaction ROLLBACK

        does NOT delete the failed-login audit event.

        Audit persistence failure must never convert a normal authentication
        failure into HTTP 500.

        The caller still receives the generic authentication error.
        """

        try:
            await self._write_audit(
                self._failure_audit,
                AuditRecord(
                    action="authentication.login",
                    outcome="failure",
                    request_id=request_id,
                    source_ip=ip_address,
                    metadata={
                        "reason": reason,
                    },
                ),
            )

        except Exception:
            # Authentication failure must remain generic even when the audit
            # database is temporarily unavailable.
            #
            # Never expose:
            #
            # - database exception
            # - SQL details
            # - connection details
            # - repository implementation details
            #
            # to the authentication caller.
            logger.exception(
                "Unable to persist failed authentication audit event.",
                extra={
                    "request_id": request_id,
                    "source_ip": ip_address,
                    "reason": reason,
                },
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
        Authenticate credentials and create a JWT-backed session.

        All credential failures are deliberately normalized to:

            AuthenticationError("Invalid credentials.")

        This prevents username/account enumeration through the API.
        """

        normalized = login.strip().lower()

        # --------------------------------------------------------------------
        # Empty login
        # --------------------------------------------------------------------

        if not normalized:
            await self._audit_login_failure(
                request_id=request_id,
                ip_address=ip_address,
            )

            raise AuthenticationError(
                "Invalid credentials."
            )

        try:
            # ----------------------------------------------------------------
            # Retrieve user
            # ----------------------------------------------------------------

            user = await self._users.get_by_login(
                normalized,
            )

            valid_user = (
                user is not None
                and user.is_active
                and not user.is_locked
            )

            password_valid = False

            # ----------------------------------------------------------------
            # Verify password
            # ----------------------------------------------------------------

            if user is not None:
                try:
                    password_valid = self._passwords.verify(
                        password,
                        user.password_hash,
                    )

                except ValueError:
                    # PasswordHasher may reject malformed/too-short input
                    # with ValueError.
                    #
                    # This is an authentication failure, NOT an API 500.
                    password_valid = False

            # ----------------------------------------------------------------
            # Generic authentication failure
            # ----------------------------------------------------------------

            if not valid_user or not password_valid:
                await self._audit_login_failure(
                    request_id=request_id,
                    ip_address=ip_address,
                    reason="invalid_credentials",
                )

                raise AuthenticationError(
                    "Invalid credentials."
                )

            # ----------------------------------------------------------------
            # Resolve effective permissions
            # ----------------------------------------------------------------

            permissions = self._roles.permissions_for(
                user.roles,
            )

            # ----------------------------------------------------------------
            # Create authentication session
            # ----------------------------------------------------------------

            now = datetime.now(timezone.utc)

            session = SessionRecord(
                session_id=uuid4(),
                user_id=user.user_id,
                token_id="pending",
                created_at=now,
                expires_at=now + self._session_ttl,
                revoked_at=None,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            session = await self._sessions.create(
                session,
            )

            # ----------------------------------------------------------------
            # Issue JWT
            # ----------------------------------------------------------------

            token = self._tokens.issue(
                user.user_id,
                session.session_id,
            )

            # ----------------------------------------------------------------
            # Extract JWT JTI
            # ----------------------------------------------------------------

            claims = self._tokens.decode(
                token,
            )

            # ----------------------------------------------------------------
            # Bind JWT JTI to persisted session
            # ----------------------------------------------------------------

            session = await self._sessions.bind_token(
                session.session_id,
                claims.token_id,
            )

            # ----------------------------------------------------------------
            # Construct authenticated principal
            # ----------------------------------------------------------------

            principal = UserPrincipal(
                user_id=user.user_id,
                username=user.username,
                roles=user.roles,
                permissions=permissions,
                session_id=session.session_id,
            )

            # ----------------------------------------------------------------
            # Successful-login audit
            #
            # This remains on the normal request transaction.
            # Successful login requests complete with HTTP 200 and therefore
            # the request transaction is committed normally.
            # ----------------------------------------------------------------

            await self._audit_record(
                AuditRecord(
                    action="authentication.login",
                    outcome="success",
                    actor_user_id=user.user_id,
                    session_id=session.session_id,
                    request_id=request_id,
                    source_ip=ip_address,
                )
            )

            return LoginResult(
                access_token=token,
                principal=principal,
            )

        except AuthenticationError:
            raise

        except AuthenticationRepositoryError:
            # ----------------------------------------------------------------
            # Authentication infrastructure failure
            #
            # This is deliberately not exposed to the client.
            # ----------------------------------------------------------------

            await self._audit_login_failure(
                request_id=request_id,
                ip_address=ip_address,
                reason="authentication_repository_failure",
            )

            raise AuthenticationError(
                "Authentication service unavailable."
            ) from None

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
        Validate JWT, session state and user state.

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
        - active account
        - locked account
        - JWT subject/session binding
        - JWT JTI/session binding
        """

        try:
            # ----------------------------------------------------------------
            # Decode and validate JWT
            # ----------------------------------------------------------------

            claims = self._tokens.decode(
                access_token,
            )

            # ----------------------------------------------------------------
            # Resolve active server-side session
            # ----------------------------------------------------------------

            session = await self._sessions.get_active(
                claims.session_id,
            )

            if session is None:
                raise TokenError(
                    "Authentication session is not active."
                )

            # ----------------------------------------------------------------
            # User/session binding
            # ----------------------------------------------------------------

            if session.user_id != claims.subject:
                raise TokenError(
                    "Token/session subject mismatch."
                )

            # ----------------------------------------------------------------
            # JWT/session JTI binding
            # ----------------------------------------------------------------

            if session.token_id != claims.token_id:
                raise TokenError(
                    "Token/session identifier mismatch."
                )

            # ----------------------------------------------------------------
            # Resolve current user
            # ----------------------------------------------------------------

            user = await self._users.get_by_id(
                claims.subject,
            )

            if user is None:
                raise TokenError(
                    "User does not exist."
                )

            if not user.is_active:
                raise TokenError(
                    "User is inactive."
                )

            if user.is_locked:
                raise TokenError(
                    "User is locked."
                )

            # ----------------------------------------------------------------
            # Resolve current permissions
            # ----------------------------------------------------------------

            permissions = self._roles.permissions_for(
                user.roles,
            )

            return UserPrincipal(
                user_id=user.user_id,
                username=user.username,
                roles=user.roles,
                permissions=permissions,
                session_id=session.session_id,
            )

        except (
            TokenError,
            AuthenticationRepositoryError,
            ValueError,
        ):
            # ----------------------------------------------------------------
            # Token validation failures are audit-worthy.
            # ----------------------------------------------------------------

            try:
                await self._audit_record(
                    AuditRecord(
                        action="authentication.token_validation",
                        outcome="failure",
                        request_id=request_id,
                        metadata={
                            "reason": "invalid_token_or_session",
                        },
                    )
                )

            except Exception:
                # Never allow audit failure to expose authentication internals.
                logger.exception(
                    "Unable to persist token validation failure audit event.",
                    extra={
                        "request_id": request_id,
                    },
                )

            raise AuthenticationError(
                "Authentication failed."
            ) from None

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
        """

        try:
            revoked = await self._sessions.revoke(
                principal.session_id,
            )

            await self._audit_record(
                AuditRecord(
                    action="authentication.logout",
                    outcome=(
                        "success"
                        if revoked
                        else "failure"
                    ),
                    actor_user_id=principal.user_id,
                    session_id=principal.session_id,
                    request_id=request_id,
                    source_ip=ip_address,
                )
            )

            return revoked

        except AuthenticationRepositoryError:
            # ---------------------------------------------------------------
            # Record logout failure where possible.
            # ---------------------------------------------------------------

            try:
                await self._audit_record(
                    AuditRecord(
                        action="authentication.logout",
                        outcome="failure",
                        actor_user_id=principal.user_id,
                        session_id=principal.session_id,
                        request_id=request_id,
                        source_ip=ip_address,
                        metadata={
                            "reason": "session_repository_failure",
                        },
                    )
                )

            except Exception:
                logger.exception(
                    "Unable to persist logout failure audit event.",
                    extra={
                        "user_id": str(principal.user_id),
                        "session_id": str(principal.session_id),
                        "request_id": request_id,
                    },
                )

            raise AuthenticationError(
                "Unable to complete logout."
            ) from None

    # ========================================================================
    # Revoke all sessions
    # ========================================================================

    async def revoke_all_sessions(
        self,
        user_id: UUID,
    ) -> int:
        """
        Revoke every active authentication session for a user.
        """

        try:
            count = await self._sessions.revoke_user_sessions(
                user_id,
            )

            await self._audit_record(
                AuditRecord(
                    action="authentication.sessions_revoked",
                    outcome="success",
                    target_user_id=user_id,
                    metadata={
                        "count": count,
                    },
                )
            )

            return count

        except AuthenticationRepositoryError:
            try:
                await self._audit_record(
                    AuditRecord(
                        action="authentication.sessions_revoked",
                        outcome="failure",
                        target_user_id=user_id,
                        metadata={
                            "reason": "session_repository_failure",
                        },
                    )
                )

            except Exception:
                logger.exception(
                    "Unable to persist session revocation audit event.",
                    extra={
                        "user_id": str(user_id),
                    },
                )

            raise AuthenticationError(
                "Unable to revoke authentication sessions."
            ) from None
