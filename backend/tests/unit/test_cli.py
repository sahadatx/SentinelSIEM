from typer.testing import CliRunner

from app.cli.main import cli

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(cli, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip()
