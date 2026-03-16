"""Attack command with sequenced methods."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from ...cli.commands.logging_utils import write_logbook
from ...core.codec import base64url_encode
from ...core.parse import parse_compact_jwt
from ...models.attack_enums import (
    AttackCommand,
    AttackError,
    AttackHelp,
    AttackName,
    AttackOptionHelp,
    AttackReason,
    DiffKind,
    DiffSection,
    HelpFlag,
    KidArg,
    OutputKey,
)
from ...models.log_enums import LogEvent
from ...workflows.claim_injection import claim_injection_value_variants, claim_injection_variants
from ...workflows.error_forcing import malformed_variants
from ...workflows.scan_playbooks import attack_variants, basic_playbook

attack_app = typer.Typer(
    help="Generate attack variant tokens for JWT security testing.",
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    rich_markup_mode="rich",
)


def _dump_json(value: Any, pretty: bool) -> None:
    if pretty:
        typer.echo(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        typer.echo(json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True))


def _attack_map() -> dict[str, AttackName]:
    return {attack.value: attack for attack in AttackName}


def _attack_help_map() -> dict[AttackName, AttackHelp]:
    return {
        AttackName.ALG_CONFUSION: AttackHelp.ALG_CONFUSION,
        AttackName.ALG_DOWNGRADE: AttackHelp.ALG_DOWNGRADE,
        AttackName.TYP_CTY: AttackHelp.TYP_CTY,
        AttackName.DUP_HEADER: AttackHelp.DUP_HEADER,
        AttackName.JWS_JWE: AttackHelp.JWS_JWE,
        AttackName.KID: AttackHelp.KID,
        AttackName.B64: AttackHelp.B64,
        AttackName.ALL: AttackHelp.ALL,
    }


def _parse_attack_sequence(methods: list[str]) -> list[tuple[AttackName, list[str]]]:
    mapping = _attack_map()
    sequence: list[tuple[AttackName, list[str]]] = []
    index = 0

    while index < len(methods):
        name = methods[index]
        attack = mapping.get(name)
        if attack is None:
            raise typer.BadParameter(f"{AttackError.UNKNOWN_ATTACK.value}: {name}")
        index += 1

        args: list[str] = []
        while index < len(methods) and methods[index] not in mapping:
            args.append(methods[index])
            index += 1
        sequence.append((attack, args))

    return sequence


def _parse_kid_args(args: list[str]) -> list[str]:
    extras: list[str] = []
    index = 0
    while index < len(args):
        value = args[index]
        if value != KidArg.EXTRA.value:
            raise typer.BadParameter(AttackError.KID_EXTRA_ONLY.value)
        if index + 1 >= len(args):
            raise typer.BadParameter(AttackError.KID_EXTRA_VALUE.value)
        extras.append(args[index + 1])
        index += 2
    return extras


def _parse_inject_claim(entries: list[str]) -> tuple[dict[str, str], dict[str, list[str]]]:
    wordlists: dict[str, str] = {}
    values: dict[str, list[str]] = {}

    for entry in entries:
        if "=" not in entry:
            raise typer.BadParameter(AttackError.INJECT_CLAIM_FORMAT.value)
        claim, value = entry.split("=", 1)
        path = Path(value)
        if path.is_file():
            wordlists[claim] = value
        else:
            values.setdefault(claim, []).append(value)

    return wordlists, values


@attack_app.callback(invoke_without_command=True)
def attack_command(
    ctx: typer.Context,
    token: str | None = typer.Option(None, "-t", "--token", help=AttackOptionHelp.TOKEN.value),
    malformed: bool = typer.Option(False, "--malformed", "-m", help=AttackOptionHelp.MALFORMED.value),
    inject_claim: list[str] = typer.Option(
        [],
        "--inject-claim",
        help=AttackOptionHelp.INJECT_CLAIM.value,
    ),
    logbook: str | None = typer.Option(None, "--logbook", "-l", help=AttackOptionHelp.LOGBOOK.value),
    pretty: bool = typer.Option(True, "--pretty/--compact", help=AttackOptionHelp.PRETTY.value),
    methods: list[str] = typer.Argument(None),
) -> None:
    if ctx.invoked_subcommand is not None:
        return

    if methods == [AttackCommand.LIST.value] and token is None:
        _dump_json({OutputKey.ATTACKS.value: [attack.value for attack in AttackName]}, pretty)
        return

    if methods and methods[-1] in {HelpFlag.LONG.value, HelpFlag.SHORT.value}:
        help_target = methods[0]
        attack = _attack_map().get(help_target)
        if attack is None:
            raise typer.BadParameter(f"{AttackError.UNKNOWN_ATTACK.value}: {help_target}")
        help_line = _attack_help_map()[attack].value
        _dump_json({OutputKey.HELP.value: help_line}, pretty)
        return

    if not token:
        raise typer.BadParameter(AttackError.PROVIDE_TOKEN.value)
    if not methods:
        raise typer.BadParameter(AttackError.PROVIDE_METHOD.value)

    if AttackCommand.LIST.value in methods:
        raise typer.BadParameter(AttackError.LIST_COMBINATION.value)

    sequence = _parse_attack_sequence(methods)
    variants: list[dict[str, Any]] = []

    original = parse_compact_jwt(token)
    original_snapshot = _token_snapshot(original)

    for attack, args in sequence:
        if attack == AttackName.ALL:
            if len(sequence) > 1:
                raise typer.BadParameter(AttackError.ALL_ALONE.value)
            entries = basic_playbook(token)
        else:
            extra_kid = _parse_kid_args(args) if attack == AttackName.KID else None
            entries = attack_variants(token, attack, extra_kid=extra_kid)

        for entry in entries:
            variant_snapshot = _token_snapshot(parse_compact_jwt(entry.token))
            diff_items = _diff_snapshot(original_snapshot, variant_snapshot)
            variants.append(
                {
                    OutputKey.ID.value: entry.variant_id,
                    OutputKey.REASON.value: entry.reason.value,
                    OutputKey.TOKEN.value: entry.token,
                    OutputKey.HEADER.value: variant_snapshot[OutputKey.HEADER.value],
                    OutputKey.PAYLOAD.value: variant_snapshot[OutputKey.PAYLOAD.value],
                    OutputKey.PARTS.value: variant_snapshot[OutputKey.PARTS.value],
                    OutputKey.DIFF.value: diff_items,
                }
            )

    if malformed:
        for index, value in enumerate(malformed_variants(token), start=1):
            parsed = None
            if value.count(".") in {1, 2}:
                try:
                    parsed = parse_compact_jwt(value)
                except Exception:
                    parsed = None
            snapshot = _token_snapshot(parsed) if parsed else _malformed_snapshot(value)
            diff_items = _diff_snapshot(original_snapshot, snapshot)
            variants.append(
                {
                    OutputKey.ID.value: f"{AttackReason.MALFORMED.value}-{index}",
                    OutputKey.REASON.value: AttackReason.MALFORMED.value,
                    OutputKey.TOKEN.value: value,
                    OutputKey.HEADER.value: snapshot.get(OutputKey.HEADER.value),
                    OutputKey.PAYLOAD.value: snapshot.get(OutputKey.PAYLOAD.value),
                    OutputKey.PARTS.value: snapshot.get(OutputKey.PARTS.value),
                    OutputKey.DIFF.value: diff_items,
                }
            )

    if inject_claim:
        wordlists, values = _parse_inject_claim(inject_claim)
        injected = []
        if wordlists:
            injected.extend(claim_injection_variants(token, wordlists))
        if values:
            injected.extend(claim_injection_value_variants(token, values))

        for variant in injected:
            variant_snapshot = _token_snapshot(parse_compact_jwt(variant.token))
            diff_items = _diff_snapshot(original_snapshot, variant_snapshot)
            variants.append(
                {
                    OutputKey.ID.value: variant.variant_id,
                    OutputKey.REASON.value: variant.reason.value,
                    OutputKey.TOKEN.value: variant.token,
                    OutputKey.HEADER.value: variant_snapshot[OutputKey.HEADER.value],
                    OutputKey.PAYLOAD.value: variant_snapshot[OutputKey.PAYLOAD.value],
                    OutputKey.PARTS.value: variant_snapshot[OutputKey.PARTS.value],
                    OutputKey.DIFF.value: diff_items,
                    OutputKey.CLAIM.value: variant.claim,
                    OutputKey.VALUE.value: variant.value,
                }
            )

    if logbook:
        write_logbook(
            logbook,
            {
                OutputKey.EVENT.value: LogEvent.ATTACK.value,
                OutputKey.VARIANT_COUNT.value: len(variants),
            },
            token=token,
        )

    _dump_json({OutputKey.VARIANTS.value: variants}, pretty)


def _payload_snapshot(payload: Any) -> Any:
    if isinstance(payload, bytes):
        return {OutputKey.VALUE.value: base64url_encode(payload)}
    return payload


def _token_snapshot(parsed: Any) -> dict[str, Any]:
    return {
        OutputKey.HEADER.value: parsed.header,
        OutputKey.PAYLOAD.value: _payload_snapshot(parsed.payload),
        OutputKey.PARTS.value: {
            OutputKey.HEADER_B64.value: parsed.parts.header_b64,
            OutputKey.PAYLOAD_B64.value: parsed.parts.payload_b64,
            OutputKey.SIGNATURE_B64.value: parsed.parts.signature_b64,
        },
    }


def _malformed_snapshot(token: str) -> dict[str, Any]:
    return {
        OutputKey.HEADER.value: None,
        OutputKey.PAYLOAD.value: None,
        OutputKey.PARTS.value: {
            OutputKey.HEADER_B64.value: None,
            OutputKey.PAYLOAD_B64.value: None,
            OutputKey.SIGNATURE_B64.value: None,
        },
    }


def _diff_dict(
    section: DiffSection,
    original: Any,
    updated: Any,
) -> list[dict[str, Any]]:
    if not isinstance(original, dict) or not isinstance(updated, dict):
        return [
            {
                OutputKey.SECTION.value: section.value,
                OutputKey.KIND.value: DiffKind.NON_JSON.value,
            }
        ]

    changes: list[dict[str, Any]] = []
    original_keys = set(original)
    updated_keys = set(updated)

    for key in sorted(original_keys - updated_keys):
        changes.append(
            {
                OutputKey.SECTION.value: section.value,
                OutputKey.FIELD.value: key,
                OutputKey.KIND.value: DiffKind.REMOVED.value,
                OutputKey.BEFORE.value: original[key],
            }
        )

    for key in sorted(updated_keys - original_keys):
        changes.append(
            {
                OutputKey.SECTION.value: section.value,
                OutputKey.FIELD.value: key,
                OutputKey.KIND.value: DiffKind.ADDED.value,
                OutputKey.AFTER.value: updated[key],
            }
        )

    for key in sorted(original_keys & updated_keys):
        if original[key] != updated[key]:
            changes.append(
                {
                    OutputKey.SECTION.value: section.value,
                    OutputKey.FIELD.value: key,
                    OutputKey.KIND.value: DiffKind.CHANGED.value,
                    OutputKey.BEFORE.value: original[key],
                    OutputKey.AFTER.value: updated[key],
                }
            )

    return changes


def _diff_snapshot(original: dict[str, Any], updated: dict[str, Any]) -> list[dict[str, Any]]:
    header_diff = _diff_dict(
        DiffSection.HEADER,
        original.get(OutputKey.HEADER.value),
        updated.get(OutputKey.HEADER.value),
    )
    payload_diff = _diff_dict(
        DiffSection.PAYLOAD,
        original.get(OutputKey.PAYLOAD.value),
        updated.get(OutputKey.PAYLOAD.value),
    )
    return header_diff + payload_diff
