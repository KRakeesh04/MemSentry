"""Normalise loaded module rows from Volatility's DLL/library plugins."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from memsentry.volatility.plugins._parser_utils import (
    VolatilityPluginParseError,
    decode_rows,
    first_value,
    normalise_os,
    normalise_values,
    optional_int,
    optional_pid,
    optional_text,
    provenance,
    walk_rows,
)

DlllistParseError = VolatilityPluginParseError


@dataclass(frozen=True, slots=True)
class ModuleArtifact:
    pid: int | None
    process_name: str | None
    module_name: str | None
    base_address: str | None
    size: int | None
    path: str | None
    original_data: dict[str, Any]
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class DlllistParseResult:
    modules: tuple[ModuleArtifact, ...]
    warnings: tuple[str, ...]


class DlllistParser:
    _SUPPORTED_OS: ClassVar[frozenset[str]] = frozenset({"windows", "linux", "mac"})
    _PLUGIN_NAMES: ClassVar[dict[str, str]] = {
        "windows": "windows.dlllist.DllList",
        "linux": "linux.elfs.Elfs",
        "mac": "mac.list_files.List_Files",
    }

    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> DlllistParseResult:
        os_type = normalise_os(os_type, self._SUPPORTED_OS)
        modules = []
        warnings: list[str] = []
        for number, depth, row in walk_rows(decode_rows(raw_output, "dlllist")):
            values = normalise_values(row)
            pid = optional_pid(values, ("pid", "processid"), "dlllist", number, warnings)
            if first_value(values, ("pid", "processid")) is not None and pid is None:
                continue
            modules.append(
                ModuleArtifact(
                    pid,
                    optional_text(values, ("process", "processname")),
                    optional_text(values, ("dllname", "modulename", "name", "path")),
                    optional_text(values, ("base", "baseaddress", "start")),
                    optional_int(values, ("size",)),
                    optional_text(values, ("path", "location", "fullname")),
                    dict(row),
                    provenance(self._PLUGIN_NAMES[os_type], number, depth),
                )
            )
        return DlllistParseResult(tuple(modules), tuple(warnings))


DllListParser = DlllistParser
