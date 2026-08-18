from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from getpass import getpass
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.adapters import AuthUser, AuthUserRole
from app.auth.password import PasswordHasher
from app.auth.roles import Role
from app.storage.postgres.session import PostgresSessionManager


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def required_env(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise RuntimeError(
            f"Required environment variable {name!r} is not set."
        )

    return value


def read_password(label: str) -> str:
    password = getpass(label)

    if len(password) < 12:
        raise ValueError(
            "Password must contain at least 12 characters."
        )

    return password


async def ensure_role_exists(
    session: AsyncSession,
    role: Role,
) -> None:
    result = await session.execute(
        text(
            """
            SELECT 1
            FROM siem_roles
            WHERE role_name = :role_name
            """
        ),
        {"role_name": role.value},
    )

    if result.first() is None:
        raise RuntimeError(
            f"Role {role.value!r} does not exist. "
            "Apply backend/app/storage/migrations/002_authentication.sql first."
        )


async def create_or_update_user(
    session: AsyncSession,
    *,
    username: str,
    email: str,
    password: str,
    role: Role,
) -> None:
    password_hasher = PasswordHasher()

    username = username.strip().lower()
    email = email.strip().lower()

    if not username:
        raise ValueError("Username cannot be empty.")

    if not email:
        raise ValueError("Email cannot be empty.")

    await ensure_role_exists(
        session,
        role,
    )

    result = await session.execute(
        select(AuthUser).where(
            (AuthUser.username == username)
            | (AuthUser.email == email)
        )
    )

    user = result.scalar_one_or_none()

    password_hash = password_hasher.hash(
        password,
    )

    if user is None:
        now = utcnow()

        user = AuthUser(
            user_id=uuid4(),
            username=username,
            email=email,
            password_hash=password_hash,
            is_active=True,
            is_locked=False,
            failed_login_count=0,
            created_at=now,
            updated_at=now,
        )

        session.add(user)
        await session.flush()

        print(
            f"Created user: {username} [{role.value}]"
        )

    else:
        user.username = username
        user.email = email
        user.password_hash = password_hash
        user.is_active = True
        user.is_locked = False
        user.failed_login_count = 0
        user.updated_at = utcnow()

        await session.flush()

        print(
            f"Updated user: {username} [{role.value}]"
        )

    role_result = await session.execute(
        select(AuthUserRole).where(
            AuthUserRole.user_id == user.user_id,
            AuthUserRole.role_name == role.value,
        )
    )

    if role_result.scalar_one_or_none() is None:
        session.add(
            AuthUserRole(
                user_id=user.user_id,
                role_name=role.value,
            )
        )

        await session.flush()

        print(
            f"Assigned role: {username} -> {role.value}"
        )

    else:
        print(
            f"Role already assigned: {username} -> {role.value}"
        )


async def main() -> None:
    database_url = required_env(
        "SIEM_DATABASE_URL"
    )

    manager = PostgresSessionManager(
        database_url
    )

    try:
        admin_password = read_password(
            "ADMIN test password (minimum 12 chars): "
        )

        viewer_password = read_password(
            "VIEWER test password (minimum 12 chars): "
        )

        async with manager.session() as session:
            await create_or_update_user(
                session,
                username="admin",
                email="admin@sentinelsiem.local",
                password=admin_password,
                role=Role.ADMIN,
            )

            await create_or_update_user(
                session,
                username="viewer",
                email="viewer@sentinelsiem.local",
                password=viewer_password,
                role=Role.VIEWER,
            )

            await session.commit()

        print()
        print("Test users are ready.")
        print("  admin  -> ADMIN")
        print("  viewer -> VIEWER")

    finally:
        await manager.close()


if __name__ == "__main__":
    asyncio.run(main())