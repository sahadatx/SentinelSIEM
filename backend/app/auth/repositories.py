from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol
from uuid import UUID

from app.auth.models import AuditRecord, SessionRecord, UserIdentity


class UserRepository(Protocol):
    """Async repository contract for authentication identities."""

    async def get_by_login(
        self,
        login: str,
    ) -> UserIdentity | None:
        """Find a user by username or email."""

    async def get_by_id(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """Find a user by UUID."""


class SessionRepository(Protocol):
    """Async repository contract for authentication sessions."""

    async def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        """Persist a new authentication session."""

    async def get_active(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        """Return an active session."""

    async def bind_token(
        self,
        session_id: UUID,
        token_id: str,
    ) -> SessionRecord:
        """Bind a JWT token ID to a session."""

    async def revoke(
        self,
        session_id: UUID,
    ) -> bool:
        """Revoke a session."""

    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        """Revoke all sessions belonging to a user."""

    async def purge_expired(self) -> int:
        """Remove expired sessions."""


class AuthAuditRepository(Protocol):
    """Async repository contract for authentication audit events."""

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """Persist an authentication audit event."""


class AuthenticationRepositoryError(RuntimeError):
    """Base authentication repository error."""


class UserRepositoryError(AuthenticationRepositoryError):
    """Raised when user persistence fails."""


class SessionRepositoryError(AuthenticationRepositoryError):
    """Raised when session persistence fails."""


class AuthAuditRepositoryError(AuthenticationRepositoryError):
    """Raised when audit persistence fails."""


class AbstractUserRepository(ABC):
    """Optional abstract base class for concrete user repositories."""

    @abstractmethod
    async def get_by_login(
        self,
        login: str,
    ) -> UserIdentity | None:
        """Find a user by username or email."""

    @abstractmethod
    async def get_by_id(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """Find a user by UUID."""


class AbstractSessionRepository(ABC):
    """Optional abstract base class for concrete session repositories."""

    @abstractmethod
    async def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        """Persist a session."""

    @abstractmethod
    async def get_active(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        """Return an active session."""

    @abstractmethod
    async def bind_token(
        self,
        session_id: UUID,
        token_id: str,
    ) -> SessionRecord:
        """Bind JWT JTI to a session."""

    @abstractmethod
    async def revoke(
        self,
        session_id: UUID,
    ) -> bool:
        """Revoke a session."""

    @abstractmethod
    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        """Revoke all user sessions."""

    @abstractmethod
    async def purge_expired(self) -> int:
        """Remove expired sessions."""


class AbstractAuthAuditRepository(ABC):
    """Optional abstract base class for audit repositories."""

    @abstractmethod
    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """Persist an audit record."""