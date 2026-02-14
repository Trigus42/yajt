"""CLI entrypoint."""

from __future__ import annotations

import typer

from .commands.attack import attack_app
from .commands.crack import crack_app
from .commands.decode import decode_command
from .commands.edit import edit_command
from .commands.fuzz import fuzz_app
from .commands.keys import keys_app
from .commands.resign import resign_command
from .commands.validate import validate_command
from .commands.verify import verify_command

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
