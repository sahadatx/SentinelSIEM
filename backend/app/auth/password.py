from __future__ import annotations

from argon2 import PasswordHasher as Argon2PasswordHasher
from argon2.exceptions import HashingError, InvalidHash, VerificationError, VerifyMismatchError


class PasswordHashError(ValueError):
    """Raised when password hashing or verification cannot be completed safely."""


class PasswordHasher:
    """Argon2id password hashing facade.

    Passwords are never persisted or logged in plaintext. Argon2id parameters
    are embedded in the encoded hash, allowing safe verification without
    process-global password configuration.
    """

    algorithm = "argon2id"

    def __init__(self) -> None:
        self._hasher = Argon2PasswordHasher(
            time_cost=3,
            memory_cost=64 * 1024,
            parallelism=2,
            hash_len=32,
            salt_len=16,
        )

    def hash(self, password: str) -> str:
        self._validate_password(password)
        try:
            return self._hasher.hash(password)
        except (HashingError, ValueError) as exc:
            raise PasswordHashError("Password hashing failed safely.") from exc

    def verify(self, password: str, encoded: str) -> bool:
        self._validate_password(password)
        if not isinstance(encoded, str) or not encoded.startswith("$argon2id$"):
            return False
        try:
            return bool(self._hasher.verify(encoded, password))
        except (VerifyMismatchError, VerificationError, InvalidHash, ValueError):
            return False

    def needs_rehash(self, encoded: str) -> bool:
        if not isinstance(encoded, str) or not encoded.startswith("$argon2id$"):
            return True
        try:
            return self._hasher.check_needs_rehash(encoded)
        except (InvalidHash, ValueError):
            return True

    @staticmethod
    def _validate_password(password: str) -> None:
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")
        if not 12 <= len(password) <= 1024:
            raise ValueError("Password length must be between 12 and 1024 characters.")
