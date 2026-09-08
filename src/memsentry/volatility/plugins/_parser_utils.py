"""Shared, dependency-free helpers for normalising Volatility JSON output."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


class VolatilityPluginParseError(ValueError):
    """Raised when a Volatility plugin result cannot be decoded."""


def decode_rows(
    raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], plugin_name: str
) -> Sequence[Any]:
    """Decode JSON/JSON Lines output without touching the evidence image."""
    if isinstance(raw_output, Path):
        try:
            raw_output = raw_output.read_text(encoding="utf-8")
        except OSError as error:
            raise VolatilityPluginParseError(
                f"Unable to read {plugin_name} output: {error}"
            ) from error
    if isinstance(raw_output, bytes):
        try:
            raw_output = raw_output.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VolatilityPluginParseError(f"{plugin_name} output is not UTF-8 JSON.") from error
    if isinstance(raw_output, str):
        raw_output = _decode_json_document(raw_output, plugin_name)
    if isinstance(raw_output, Mapping):
        raw_output = raw_output.get("rows", raw_output.get("results", raw_output))
    if not isinstance(raw_output, Sequence) or isinstance(raw_output, (str, bytes)):
        raise VolatilityPluginParseError(f"{plugin_name} JSON must contain a list of result rows.")
    return raw_output


def walk_rows(rows: Sequence[Any]) -> tuple[tuple[int, int, Mapping[str, Any]], ...]:
    """Flatten renderer tree rows while retaining their source order and depth."""
    result: list[tuple[int, int, Mapping[str, Any]]] = []

    def visit(items: Sequence[Any], depth: int) -> None:
        for item in items:
            row_number = len(result) + 1
            if not isinstance(item, Mapping):
                result.append((row_number, depth, {}))
                continue
            row = dict(item)
            children = row.pop("__children", [])
            result.append((row_number, depth, row))
            if isinstance(children, Sequence) and not isinstance(children, (str, bytes)):
                visit(children, depth + 1)

    visit(rows, 0)
    return tuple(result)


def normalise_os(os_type: str, supported: frozenset[str]) -> str:
    normalised = os_type.strip().lower() if isinstance(os_type, str) else ""
    if normalised not in supported:
        raise VolatilityPluginParseError(
            f"Unsupported operating system '{os_type}'. Supported values: {', '.join(sorted(supported))}."
        )
    return normalised


def normalise_values(row: Mapping[str, Any]) -> dict[str, Any]:
    return {normalise_column(column): value for column, value in row.items()}


def provenance(plugin_name: str, row_number: int, tree_depth: int) -> dict[str, Any]:
    """Build the common provenance record attached to every artifact."""
    return {
        "source_plugin": plugin_name,
        "source_row": row_number,
        "source_tree_depth": tree_depth,
    }


def required_pid(
    values: Mapping[str, Any],
    pid_names: tuple[str, ...],
    plugin_name: str,
    row_number: int,
    warnings: list[str],
) -> int | None:
    """Extract a mandatory PID, recording a warning when it is missing.

    Returns ``None`` (and appends to ``warnings``) when the row has no valid
    PID, mirroring the behaviour shared by the process-oriented parsers.
    """
    pid = optional_int(values, pid_names)
    if pid is None or pid < 0:
        warnings.append(f"{plugin_name} row {row_number} has no valid PID; row skipped.")
        return None
    return pid


def optional_pid(
    values: Mapping[str, Any],
    pid_names: tuple[str, ...],
    plugin_name: str,
    row_number: int,
    warnings: list[str],
) -> int | None:
    """Extract an optional PID, recording a warning only on malformed input.

    Unlike :func:`required_pid`, a row without any PID value is valid and
    yields ``None``; a warning is emitted only when a value was present but
    could not be parsed.
    """
    pid = optional_int(values, pid_names)
    if first_value(values, pid_names) is not None and pid is None:
        warnings.append(f"{plugin_name} row {row_number} has invalid PID; row skipped.")
        return None
    return pid


def normalise_column(column: object) -> str:
    return "".join(character for character in str(column).lower() if character.isalnum())


def first_value(values: Mapping[str, Any], names: tuple[str, ...]) -> Any | None:
    for name in names:
        if name in values and values[name] is not None:
            return values[name]
    return None


def optional_text(values: Mapping[str, Any], names: tuple[str, ...]) -> str | None:
    value = first_value(values, names)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def optional_int(values: Mapping[str, Any], names: tuple[str, ...]) -> int | None:
    value = first_value(values, names)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return None
    return None


def optional_bool(values: Mapping[str, Any], names: tuple[str, ...]) -> bool | None:
    value = first_value(values, names)
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    return None


def _decode_json_document(raw_output: str, plugin_name: str) -> Any:
    text = raw_output.strip()
    if not text:
        raise VolatilityPluginParseError(f"{plugin_name} output is empty.")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        rows: list[Any] = []
        try:
            for line in text.splitlines():
                if line.strip():
                    rows.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise VolatilityPluginParseError(
                f"{plugin_name} output is not valid JSON or JSON Lines."
            ) from error
        if not rows:
            raise VolatilityPluginParseError(f"{plugin_name} output is empty.") from None
        return rows
