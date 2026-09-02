"""Normalise command-line artifacts from Volatility JSON output."""

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
    optional_text,
    provenance,
    required_pid,
    walk_rows,
)

CmdlineParseError = VolatilityPluginParseError


@dataclass(frozen=True, slots=True)
class CommandLineArtifact:
    pid: int
    process_name: str | None
    command_line: str | None
    original_data: dict[str, Any]
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class CmdlineParseResult:
    command_lines: tuple[CommandLineArtifact, ...]
    warnings: tuple[str, ...]


class CmdlineParser:
    """Parse Windows ``cmdline`` and Linux/macOS ``psaux`` output."""

    _SUPPORTED_OS: ClassVar[frozenset[str]] = frozenset({"windows", "linux", "mac"})
    _PLUGIN_NAMES: ClassVar[dict[str, str]] = {
        "windows": "windows.cmdline.CmdLine",
        "linux": "linux.psaux.PsAux",
        "mac": "mac.psaux.Psaux",
    }

    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> CmdlineParseResult:
        os_type = normalise_os(os_type, self._SUPPORTED_OS)
        command_lines: list[CommandLineArtifact] = []
        warnings: list[str] = []
        for row_number, depth, row in walk_rows(decode_rows(raw_output, "cmdline")):
            values = normalise_values(row)
            pid = required_pid(values, ("pid",), "cmdline", row_number, warnings)
            if pid is None:
                continue
            command_lines.append(
                CommandLineArtifact(
                    pid=pid,
                    process_name=optional_text(
                        values, ("process", "imagefilename", "comm", "name")
                    ),
                    command_line=optional_text(
                        values, ("args", "commandline", "command", "cmdline")
                    ),
                    original_data=dict(row),
                    provenance=provenance(self._PLUGIN_NAMES[os_type], row_number, depth),
                )
            )
        return CmdlineParseResult(tuple(command_lines), tuple(warnings))


CmdLineParser = CmdlineParser
