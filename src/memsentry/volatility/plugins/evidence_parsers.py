"""Optional Windows evidence adapters for the installed Volatility 3 output schemas.

Threads inherits ThrdScan's columns; prefer Win32StartAddress for user-mode VAD
correlation. Psscan shares PsList columns but retains its distinct scan provenance.
VadInfo uses absolute inclusive VAD endpoints, never VPN page numbers here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from memsentry.volatility.plugins._parser_utils import (
    decode_rows,
    normalise_os,
    normalise_values,
    optional_int,
    optional_text,
    provenance,
    required_pid,
    walk_rows,
)
from memsentry.volatility.plugins.malfind_parser import (
    MalfindParser,
    MalfindParseResult,
    MemoryRegionArtifact,
)
from memsentry.volatility.plugins.pslist_parser import PsListParser, PsListParseResult


@dataclass(frozen=True, slots=True)
class ThreadArtifact:
    pid: int
    tid: int | None
    start_address: int | None
    start_address_source: str
    kernel_start_address: int | None
    address_space: str
    thread_creation_time: str | None
    thread_exit_time: str | None
    original_data: dict[str, Any]
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ThreadsParseResult:
    threads: tuple[ThreadArtifact, ...]
    warnings: tuple[str, ...]


class ThreadsParser:
    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> ThreadsParseResult:
        normalise_os(os_type, frozenset({"windows"}))
        threads = []
        warnings: list[str] = []
        for number, depth, row in walk_rows(decode_rows(raw_output, "threads")):
            values = normalise_values(row)
            pid = required_pid(values, ("pid",), "threads", number, warnings)
            if pid is None:
                continue
            user_start = optional_int(values, ("win32startaddress",))
            kernel_start = optional_int(values, ("startaddress",))
            if user_start is None and kernel_start is None:
                warnings.append(f"threads row {number}: start address unavailable")
            threads.append(
                ThreadArtifact(
                    pid,
                    optional_int(values, ("tid",)),
                    user_start or kernel_start,
                    "Win32StartAddress" if user_start else "StartAddress",
                    kernel_start,
                    "process_virtual",
                    optional_text(values, ("createtime",)),
                    optional_text(values, ("exittime",)),
                    dict(row),
                    provenance("windows.threads.Threads", number, depth),
                )
            )
        return ThreadsParseResult(tuple(threads), tuple(warnings))


class PsScanParser:
    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> PsListParseResult:
        normalise_os(os_type, frozenset({"windows"}))
        parsed = PsListParser().parse(raw_output, os_type)
        return PsListParseResult(
            tuple(
                replace(
                    a,
                    provenance={
                        **a.provenance,
                        "source_plugin": "windows.psscan.PsScan",
                        "process_view": "scan",
                    },
                )
                for a in parsed.processes
            ),
            parsed.warnings,
        )


@dataclass(frozen=True, slots=True)
class VadRegionArtifact(MemoryRegionArtifact):
    path: str | None = None
    backing: str = "UNKNOWN"
    end_inclusive: bool = True
    address_space: str = "process_virtual"


class VadInfoParser:
    def parse(
        self, raw_output: str | bytes | Path | Sequence[Any] | Mapping[str, Any], os_type: str
    ) -> MalfindParseResult:
        parsed = MalfindParser().parse(raw_output, os_type)
        regions = []
        for region in parsed.regions:
            values = normalise_values(region.original_data)
            path = optional_text(values, ("file",))
            fields = asdict(region)
            fields["provenance"] = {**region.provenance, "source_plugin": "windows.vadinfo.VadInfo"}
            backing = (
                "FILE_BACKED"
                if path
                else ("ANONYMOUS" if region.private_memory is True else "UNKNOWN")
            )
            regions.append(VadRegionArtifact(**fields, path=path, backing=backing))
        return MalfindParseResult(tuple(regions), parsed.warnings)
