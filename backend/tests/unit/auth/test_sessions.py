from datetime import timedelta
from uuid import uuid4
import pytest
from app.auth.sessions import SessionError, SessionStore


def test_session_lifecycle() -> None:
    store = SessionStore()
    session = store.create(user_id=uuid4(), token_id="token-1", ttl=timedelta(minutes=5))
    assert store.get_active(session.session_id).session_id == session.session_id
    assert store.revoke(session.session_id)
    with pytest.raises(SessionError):
        store.get_active(session.session_id)


def test_user_session_revocation() -> None:
    store = SessionStore()
    user_id = uuid4()
    first = store.create(user_id=user_id, token_id="a", ttl=timedelta(minutes=5))
    second = store.create(user_id=user_id, token_id="b", ttl=timedelta(minutes=5))
    assert store.revoke_user_sessions(user_id) == 2
    with pytest.raises(SessionError):
        store.get_active(first.session_id)
    with pytest.raises(SessionError):
        store.get_active(second.session_id)
