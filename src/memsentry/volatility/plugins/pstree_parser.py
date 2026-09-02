"""Normalise JSON output from Volatility's process-tree plugins."""

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

PstreeParseError = VolatilityPluginParseError


@dataclass(frozen=True, slots=True)
class ProcessTreeArtifact:
    pid: int
    process_name: str | None
    ppid: int | None
    original_data: dict[str, Any]
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PstreeParseResult:
    processes: tuple[ProcessTreeArtifact, ...]
    warnings: tuple[str, ...]


class PstreeParser:
    """Parse ``windows.pstree`` and ``linux.pstree`` renderer output."""

    _SUPPORTED_OS: ClassVar[frozenset[str]] = frozenset({"windows", "linux"})
    _PLUGIN_NAMES: ClassVar[dict[str, str]] = {
        "windows": "windows.pstree.PsTree",
        "linux": "linux.pstree.PsTree",
    }

    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> PstreeParseResult:
        os_type = normalise_os(os_type, self._SUPPORTED_OS)
        processes: list[ProcessTreeArtifact] = []
        warnings: list[str] = []
        for row_number, depth, row in walk_rows(decode_rows(raw_output, "pstree")):
            values = normalise_values(row)
            pid = optional_int(values, ("pid",))
            if pid is None or pid < 0:
                warnings.append(f"pstree row {row_number} has no valid PID; row skipped.")
                continue
            processes.append(
                ProcessTreeArtifact(
                    pid=pid,
                    process_name=optional_text(values, ("imagefilename", "comm", "name")),
                    ppid=optional_int(values, ("ppid",)),
                    original_data=dict(row),
                    provenance={
                        "source_plugin": self._PLUGIN_NAMES[os_type],
                        "source_row": row_number,
                        "source_tree_depth": depth,
                    },
                )
            )
        return PstreeParseResult(tuple(processes), tuple(warnings))


PsTreeParser = PstreeParser
