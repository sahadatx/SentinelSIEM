from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# ============================================================================
# PostgreSQL Session Manager
# ============================================================================


class PostgresSessionManager:
    """
    Async SQLAlchemy session lifecycle manager for SentinelSIEM.

    Responsibilities:

        - PostgreSQL async engine creation
        - AsyncSession factory management
        - Session lifecycle
        - Transaction lifecycle
        - Database health checks
        - Engine shutdown

    Transaction ownership:

        Repository methods do NOT commit or rollback transactions.
        The service/application layer owns the transaction boundary.

    Example:

        manager = PostgresSessionManager(database_url)

        async with manager.session() as session:
            repository = PostgresUserRepository(session)
            user = await repository.get_by_id(user_id)

        For an explicit transaction:

        async with manager.transaction() as session:
            repository = PostgresUserRepository(session)
            await repository.create_user(...)
    """

    # ------------------------------------------------------------------------
    # Defaults
    # ------------------------------------------------------------------------

    DEFAULT_POOL_SIZE = 10
    DEFAULT_MAX_OVERFLOW = 20
    DEFAULT_POOL_TIMEOUT = 30
    DEFAULT_POOL_RECYCLE = 1800

    # ------------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------------

    def __init__(
        self,
        database_url: str,
        *,
        pool_size: int = DEFAULT_POOL_SIZE,
        max_overflow: int = DEFAULT_MAX_OVERFLOW,
        pool_timeout: int = DEFAULT_POOL_TIMEOUT,
        pool_recycle: int = DEFAULT_POOL_RECYCLE,
        echo: bool = False,
    ) -> None:
        """
        Initialize the PostgreSQL session manager.

        Args:
            database_url:
                PostgreSQL asyncpg connection URL.

            pool_size:
                Number of persistent connections maintained by the pool.

            max_overflow:
                Additional temporary connections allowed above pool_size.

            pool_timeout:
                Maximum seconds to wait for a connection from the pool.

            pool_recycle:
                Recycle connections after this many seconds.

            echo:
                Enable SQLAlchemy SQL logging.

        Raises:
            ValueError:
                If the database URL or pool configuration is invalid.
        """
        self._validate_database_url(database_url)

        self._validate_pool_configuration(
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_recycle=pool_recycle,
        )

        self.database_url = database_url

        self.engine: AsyncEngine = create_async_engine(
            database_url,
            echo=echo,
            pool_pre_ping=True,
            pool_recycle=pool_recycle,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
        )

        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False,
        )

        self._closed = False

    # ------------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------------

    @staticmethod
    def _validate_database_url(database_url: str) -> None:
        """
        Validate that the configured database URL uses asyncpg.

        SentinelSIEM repositories require asynchronous PostgreSQL access.
        """
        if not isinstance(database_url, str):
            raise ValueError("database_url must be a string")

        database_url = database_url.strip()

        if not database_url:
            raise ValueError("database_url must not be empty")

        if not database_url.startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must use the postgresql+asyncpg scheme")

    @staticmethod
    def _validate_pool_configuration(
        *,
        pool_size: int,
        max_overflow: int,
        pool_timeout: int,
        pool_recycle: int,
    ) -> None:
        """Validate SQLAlchemy connection-pool configuration."""

        if not isinstance(pool_size, int):
            raise ValueError("pool_size must be an integer")

        if pool_size < 1:
            raise ValueError("pool_size must be greater than zero")

        if not isinstance(max_overflow, int):
            raise ValueError("max_overflow must be an integer")

        if max_overflow < 0:
            raise ValueError("max_overflow must not be negative")

        if not isinstance(pool_timeout, int):
            raise ValueError("pool_timeout must be an integer")

        if pool_timeout <= 0:
            raise ValueError("pool_timeout must be greater than zero")

        if not isinstance(pool_recycle, int):
            raise ValueError("pool_recycle must be an integer")

        if pool_recycle <= 0:
            raise ValueError("pool_recycle must be greater than zero")

    # ------------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------------

    @asynccontextmanager
    async def session(
        self,
    ) -> AsyncIterator[AsyncSession]:
        """
        Provide an AsyncSession.

        This context manager does NOT automatically commit.

        Commit/rollback should be controlled explicitly by the caller when
        the operation represents a transaction.
        """
        if self._closed:
            raise RuntimeError("PostgresSessionManager is closed")

        session = self.session_factory()

        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    # ------------------------------------------------------------------------
    # Transaction lifecycle
    # ------------------------------------------------------------------------

    @asynccontextmanager
    async def transaction(
        self,
    ) -> AsyncIterator[AsyncSession]:
        """
        Provide an AsyncSession with an explicit transaction boundary.

        Successful execution:

            COMMIT

        Exception:

            ROLLBACK
        """
        if self._closed:
            raise RuntimeError("PostgresSessionManager is closed")

        async with self.session_factory() as session:
            try:
                async with session.begin():
                    yield session
            except Exception:
                await session.rollback()
                raise

    # ------------------------------------------------------------------------
    # Database health
    # ------------------------------------------------------------------------

    async def ping(self) -> bool:
        """
        Verify PostgreSQL connectivity.

        Returns:
            True when SELECT 1 succeeds.

        Raises:
            SQLAlchemy database exceptions when PostgreSQL is unavailable.
        """
        if self._closed:
            raise RuntimeError("PostgresSessionManager is closed")

        async with self.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

        return True

    # ------------------------------------------------------------------------
    # Engine status
    # ------------------------------------------------------------------------

    @property
    def is_closed(self) -> bool:
        """Return whether the session manager has been closed."""
        return self._closed

    # ------------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------------

    async def close(self) -> None:
        """
        Dispose the SQLAlchemy engine.

        Safe to call more than once.
        """
        if self._closed:
            return

        await self.engine.dispose()

        self._closed = True


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "PostgresSessionManager",
]
