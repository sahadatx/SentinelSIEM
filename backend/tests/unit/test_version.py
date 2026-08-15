from app.core.version import __version__


def test_version_is_defined() -> None:
    assert __version__
    assert isinstance(__version__, str)
