"""Normalise suspicious memory-region rows from ``windows.malfind``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from memsentry.volatility.plugins._parser_utils import (
    VolatilityPluginParseError,
    decode_rows,
    normalise_os,
    normalise_values,
    optional_bool,
    optional_int,
    optional_text,
    walk_rows,
)

MalfindParseError = VolatilityPluginParseError


@dataclass(frozen=True, slots=True)
class MemoryRegionArtifact:
    pid: int
    process_name: str | None
    start: str | None
    end: str | None
    protection: str | None
    tag: str | None
    commit_charge: int | None
    private_memory: bool | None
    hexdump: str | None
    disassembly: str | None
    original_data: dict[str, Any]
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class MalfindParseResult:
    regions: tuple[MemoryRegionArtifact, ...]
    warnings: tuple[str, ...]


class MalfindParser:
    _SUPPORTED_OS = frozenset({"windows"})

    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> MalfindParseResult:
        normalise_os(os_type, self._SUPPORTED_OS)
        regions = []
        warnings = []
        for number, depth, row in walk_rows(decode_rows(raw_output, "malfind")):
            values = normalise_values(row)
            pid = optional_int(values, ("pid",))
            if pid is None or pid < 0:
                warnings.append(f"malfind row {number} has no valid PID; row skipped.")
                continue
            regions.append(
                MemoryRegionArtifact(
                    pid,
                    optional_text(values, ("process", "processname", "name")),
                    optional_text(values, ("startvpn", "start", "startaddress")),
                    optional_text(values, ("endvpn", "end", "endaddress")),
                    optional_text(values, ("protection", "protect")),
                    optional_text(values, ("tag",)),
                    optional_int(values, ("commitcharge",)),
                    optional_bool(values, ("privatememory", "private")),
                    optional_text(values, ("hexdump", "hex")),
                    optional_text(values, ("disasm", "disassembly")),
                    dict(row),
                    {
                        "source_plugin": "windows.malfind.Malfind",
                        "source_row": number,
                        "source_tree_depth": depth,
                    },
                )
            )
        return MalfindParseResult(tuple(regions), tuple(warnings))
