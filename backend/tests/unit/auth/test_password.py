from app.auth.password import PasswordHasher


def test_argon2id_hash_is_non_reversible_and_verifies() -> None:
    hasher = PasswordHasher()
    password = "Correct-Horse-Battery-7!"
    encoded = hasher.hash(password)
    assert encoded.startswith("$argon2id$")
    assert password not in encoded
    assert hasher.verify(password, encoded)
    assert not hasher.verify("Wrong-Horse-Battery-7!", encoded)


def test_password_hashes_are_salted() -> None:
    hasher = PasswordHasher()
    password = "Correct-Horse-Battery-7!"
    assert hasher.hash(password) != hasher.hash(password)
