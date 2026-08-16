from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt
from jwt import InvalidTokenError


class TokenError(ValueError):
    """Raised when a token cannot be safely accepted."""


@dataclass(frozen=True, slots=True)
class TokenClaims:
    subject: UUID
    session_id: UUID
    token_id: str
    issuer: str
    audience: str
    issued_at: datetime
    expires_at: datetime


class TokenService:
    """Strict JWT access-token service with an explicit algorithm allow-list."""

    ALLOWED_ALGORITHMS = frozenset({"HS256"})

    def __init__(self, *, secret_key: str, issuer: str = "sentinelsiem",
                 audience: str = "sentinelsiem-api", ttl: timedelta = timedelta(minutes=30),
                 algorithm: str = "HS256") -> None:
        if len(secret_key) < 32:
            raise ValueError("Authentication secret must contain at least 32 characters.")
        if algorithm not in self.ALLOWED_ALGORITHMS:
            raise ValueError("Unsupported authentication algorithm.")
        if ttl <= timedelta(0):
            raise ValueError("Token TTL must be positive.")
        self._secret = secret_key
        self._issuer = issuer
        self._audience = audience
        self._ttl = ttl
        self._algorithm = algorithm

    def issue(self, user_id: UUID, session_id: UUID, *, token_id: str | None = None,
              now: datetime | None = None) -> str:
        issued = now or datetime.now(timezone.utc)
        expires = issued + self._ttl
        jti = token_id or uuid4().hex
        payload = {
            "sub": str(user_id), "sid": str(session_id), "jti": jti,
            "iss": self._issuer, "aud": self._audience,
            "iat": int(issued.timestamp()), "exp": int(expires.timestamp()),
        }
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def decode(self, token: str) -> TokenClaims:
        if not isinstance(token, str) or not token:
            raise TokenError("Invalid access token.")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in self.ALLOWED_ALGORITHMS:
                raise TokenError("Invalid access token.")
            payload = jwt.decode(
                token, self._secret,
                algorithms=[self._algorithm], issuer=self._issuer,
                audience=self._audience, options={"require": ["sub", "sid", "jti", "iss", "aud", "iat", "exp"]},
            )
            subject = UUID(str(payload["sub"]))
            session_id = UUID(str(payload["sid"]))
            issued_at = datetime.fromtimestamp(int(payload["iat"]), tz=timezone.utc)
            expires_at = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)
            token_id = str(payload["jti"])
            if not token_id or len(token_id) > 128 or expires_at <= issued_at:
                raise TokenError("Invalid access token.")
            return TokenClaims(subject, session_id, token_id, str(payload["iss"]), str(payload["aud"]), issued_at, expires_at)
        except (InvalidTokenError, KeyError, TypeError, ValueError, OverflowError) as exc:
            if isinstance(exc, TokenError):
                raise
            raise TokenError("Invalid access token.") from exc
