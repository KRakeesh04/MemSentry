"""Normalise network connection rows from Volatility renderers."""

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
    optional_text,
    walk_rows,
)

NetscanParseError = VolatilityPluginParseError


@dataclass(frozen=True, slots=True)
class NetworkConnectionArtifact:
    protocol: str | None
    local_address: str | None
    local_port: int | None
    remote_address: str | None
    remote_port: int | None
    state: str | None
    pid: int | None
    owner: str | None
    original_data: dict[str, Any]
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class NetscanParseResult:
    connections: tuple[NetworkConnectionArtifact, ...]
    warnings: tuple[str, ...]


class NetscanParser:
    _SUPPORTED_OS: ClassVar[frozenset[str]] = frozenset({"windows", "linux", "mac"})
    _PLUGIN_NAMES: ClassVar[dict[str, str]] = {
        "windows": "windows.netscan.NetScan",
        "linux": "linux.sockstat.Sockstat",
        "mac": "mac.netstat.Netstat",
    }

    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> NetscanParseResult:
        os_type = normalise_os(os_type, self._SUPPORTED_OS)
        connections = []
        warnings = []
        for number, depth, row in walk_rows(decode_rows(raw_output, "netscan")):
            values = normalise_values(row)
            pid = optional_int(values, ("pid", "ownerpid"))
            if first_value(values, ("pid", "ownerpid")) is not None and pid is None:
                warnings.append(f"netscan row {number} has invalid PID; row skipped.")
                continue
            connections.append(
                NetworkConnectionArtifact(
                    optional_text(values, ("proto", "protocol")),
                    optional_text(values, ("localaddr", "localaddress", "local")),
                    optional_int(values, ("localport",)),
                    optional_text(values, ("foreignaddr", "remoteaddr", "remoteaddress", "remote")),
                    optional_int(values, ("foreignport", "remoteport")),
                    optional_text(values, ("state", "status")),
                    pid,
                    optional_text(values, ("owner", "process", "processname")),
                    dict(row),
                    {
                        "source_plugin": self._PLUGIN_NAMES[os_type],
                        "source_row": number,
                        "source_tree_depth": depth,
                    },
                )
            )
        return NetscanParseResult(tuple(connections), tuple(warnings))

    # Keep the OS-specific entry points from the original placeholder API.
    def linux_parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any]
    ) -> NetscanParseResult:
        return self.parse(raw_output, "linux")

    def windows_parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any]
    ) -> NetscanParseResult:
        return self.parse(raw_output, "windows")

    def mac_parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any]
    ) -> NetscanParseResult:
        return self.parse(raw_output, "mac")
