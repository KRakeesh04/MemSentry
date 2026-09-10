"""Normalise system-information rows from Volatility's ``info`` plugin."""

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
    walk_rows,
)

InfoParseError = VolatilityPluginParseError


@dataclass(frozen=True, slots=True)
class SystemInfoArtifact:
    values: dict[str, Any]
    original_data: dict[str, Any]
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class InfoParseResult:
    systems: tuple[SystemInfoArtifact, ...]
    warnings: tuple[str, ...]


class InfoParser:
    _SUPPORTED_OS: ClassVar[frozenset[str]] = frozenset({"windows", "linux", "mac"})

    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> InfoParseResult:
        os_type = normalise_os(os_type, self._SUPPORTED_OS)
        systems: list[SystemInfoArtifact] = []
        warnings: list[str] = []
        for number, depth, row in walk_rows(decode_rows(raw_output, "info")):
            if not row:
                warnings.append(f"info row {number} is empty or not an object; row skipped.")
                continue
            values = {
                key: value
                for key, value in normalise_values(row).items()
                if optional_text({"value": value}, ("value",)) is not None
            }
            systems.append(
                SystemInfoArtifact(
                    values,
                    dict(row),
                    provenance(f"{os_type}.info.Info", number, depth),
                )
            )
        return InfoParseResult(tuple(systems), tuple(warnings))
