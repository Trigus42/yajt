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

app = typer.Typer(help="YAJT - Yet Another JWT Tool")

app.command("decode")(decode_command)
app.command("edit")(edit_command)
app.command("validate")(validate_command)
app.command("verify")(verify_command)
app.command("resign")(resign_command)
app.add_typer(attack_app, name="attack")
app.add_typer(keys_app, name="keys")
app.add_typer(fuzz_app, name="fuzz")
app.add_typer(crack_app, name="crack")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
