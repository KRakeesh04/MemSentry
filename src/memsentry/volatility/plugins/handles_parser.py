"""Normalise process handle rows from Windows ``handles`` output."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from memsentry.volatility.plugins._parser_utils import (
    VolatilityPluginParseError,
    decode_rows,
    normalise_os,
    normalise_values,
    optional_int,
    optional_text,
    walk_rows,
)

HandlesParseError = VolatilityPluginParseError


@dataclass(frozen=True, slots=True)
class HandleArtifact:
    pid: int
    handle: str | None
    handle_type: str | None
    name: str | None
    access: str | None
    original_data: dict[str, Any]
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class HandlesParseResult:
    handles: tuple[HandleArtifact, ...]
    warnings: tuple[str, ...]


class HandlesParser:
    _SUPPORTED_OS: ClassVar[frozenset[str]] = frozenset({"windows"})

    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> HandlesParseResult:
        normalise_os(os_type, self._SUPPORTED_OS)
        handles = []
        warnings = []
        for number, depth, row in walk_rows(decode_rows(raw_output, "handles")):
            values = normalise_values(row)
            pid = optional_int(values, ("pid",))
            if pid is None or pid < 0:
                warnings.append(f"handles row {number} has no valid PID; row skipped.")
                continue
            handles.append(
                HandleArtifact(
                    pid,
                    optional_text(values, ("handle", "value")),
                    optional_text(values, ("type", "handletype")),
                    optional_text(values, ("name", "object")),
                    optional_text(values, ("access", "grantedaccess")),
                    dict(row),
                    {
                        "source_plugin": "windows.handles.Handles",
                        "source_row": number,
                        "source_tree_depth": depth,
                    },
                )
            )
        return HandlesParseResult(tuple(handles), tuple(warnings))
