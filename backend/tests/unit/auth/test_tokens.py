from uuid import uuid4
import pytest
from app.auth.tokens import TokenError, TokenService


def service() -> TokenService:
    return TokenService(secret_key="development-only-secret-that-is-at-least-32-chars", issuer="sentinelsiem", audience="sentinelsiem-api")


def test_issue_and_decode_round_trip() -> None:
    token_service = service()
    token = token_service.issue(uuid4(), uuid4())
    claims = token_service.decode(token)
    assert claims.issuer == "sentinelsiem"
    assert claims.audience == "sentinelsiem-api"
    assert claims.expires_at > claims.issued_at


def test_wrong_secret_is_rejected() -> None:
    token = service().issue(uuid4(), uuid4())
    attacker = TokenService(secret_key="different-secret-that-is-at-least-32-chars-long")
    with pytest.raises(TokenError):
        attacker.decode(token)
