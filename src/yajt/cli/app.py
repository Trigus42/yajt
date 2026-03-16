"""CLI entrypoint."""

from __future__ import annotations

import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import typer

from yajt.cli.commands.attack import attack_app
from yajt.cli.commands.crack import crack_app
from yajt.cli.commands.decode import decode_command
from yajt.cli.commands.edit import edit_command
from yajt.cli.commands.fuzz import fuzz_app
from yajt.cli.commands.keys import keys_app
from yajt.cli.commands.resign import resign_command
from yajt.cli.commands.validate import validate_command
from yajt.cli.commands.verify import verify_command

_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo("yajt 0.1.0")
        raise typer.Exit()


app = typer.Typer(
    help="YAJT - Yet Another JWT Tool: decode, validate, verify, resign, and attack JWTs.",
    context_settings=_CONTEXT_SETTINGS,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


@app.callback()
def _main_callback(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit.", callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


app.command("decode", help="Decode and inspect a JWT token.")(decode_command)
app.command("edit", help="Edit JWT header and/or payload interactively.")(edit_command)
app.command("validate", help="Validate JWT structure and optionally claims.")(validate_command)
app.command("verify", help="Verify JWT signature against a key or JWKS.")(verify_command)
app.command("resign", help="Re-sign a JWT with a new key and algorithm.")(resign_command)
app.add_typer(attack_app, name="attack")
app.add_typer(keys_app, name="keys")
app.add_typer(fuzz_app, name="fuzz")
app.add_typer(crack_app, name="crack")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
