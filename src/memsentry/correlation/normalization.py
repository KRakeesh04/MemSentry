"""Read-only normalized views. Unknown values stay unknown; source rows are never edited."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from memsentry.models.artifact import Artifact

ARTIFACT_TYPES = frozenset(
    {
        "process",
        "process_tree",
        "memory_region",
        "thread",
        "module",
        "network_connection",
        "command_line",
        "signature_match",
        "process_access",
        "handle",
        "process_handle",
        "remote_thread",
        "process_memory_write",
        "process_tampering",
        "windows_event",
        "authentication_event",
        "file_creation",
        "dump_file",
        "image_memory_comparison",
        "memory_protection_transition",
        "edr_event",
        "process_view",
        "system_info",
    }
)


def integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, int):
            return value if value >= 0 else None
        text = str(value).strip()
        result = int(text, 16 if text.lower().startswith("0x") else 10)
        return result if result >= 0 else None
    except (ValueError, TypeError):
        return None


def boolean(value: Any) -> bool | None:
    if value is True or value == 1 or value == "true":
        return True
    if value is False or value == 0 or value == "false":
        return False
    return None


def executable(value: Any) -> bool | None:
    """Windows base protection (ignore modifiers), or exact POSIX rwx permissions."""
    number = integer(value)
    if number is not None:
        base = number & 0xFF
        return base in {0x10, 0x20, 0x40, 0x80} if base in {1, 2, 4, 8, 16, 32, 64, 128} else None
    if not isinstance(value, str):
        return None
    text = value.strip().upper().split("|")[0].strip()
    if text.startswith("PAGE_"):
        return (
            text
            in {
                "PAGE_EXECUTE",
                "PAGE_EXECUTE_READ",
                "PAGE_EXECUTE_READWRITE",
                "PAGE_EXECUTE_WRITECOPY",
            }
            if text
            in {
                "PAGE_NOACCESS",
                "PAGE_READONLY",
                "PAGE_READWRITE",
                "PAGE_WRITECOPY",
                "PAGE_EXECUTE",
                "PAGE_EXECUTE_READ",
                "PAGE_EXECUTE_READWRITE",
                "PAGE_EXECUTE_WRITECOPY",
            }
            else None
        )
    if re.fullmatch(r"[r-][w-][x-][ps-]?", value):
        return value[2] == "x"
    return None


def timestamp(value: Any) -> datetime | None:
    """Reject naive timestamps rather than guessing a timezone or using ingestion time."""
    try:
        result = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
        return result.astimezone(UTC) if result.tzinfo is not None else None
    except (ValueError, TypeError):
        return None


def basename(value: Any) -> str | None:
    return str(value).replace("\\", "/").rsplit("/", 1)[-1].lower() if value else None


@dataclass(slots=True)
class NormalizedArtifact:
    artifact: Artifact
    data: dict[str, Any]
    scope: tuple[str, str, str]
    instance: str | None = None
    identity_strength: str = "unresolved"

    @property
    def id(self) -> str:
        return str(self.artifact.id)

    @property
    def kind(self) -> str:
        return self.artifact.artifact_type


def normalize(artifact: Artifact) -> NormalizedArtifact:
    raw = artifact.original_data
    nested = raw.get("normalized", {})
    data = {**artifact.provenance, **raw, **(nested if isinstance(nested, dict) else {})}
    data.pop("normalized", None)
    if artifact.artifact_type in {"process_access", "remote_thread", "process_memory_write"}:
        data.setdefault("pid", data.get("source_pid"))
        data.setdefault("process_guid", data.get("source_process_guid"))
        data.setdefault("process_creation_time", data.get("source_creation_time"))
        data.setdefault("process_name", basename(data.get("source_image")))
    data["pid"] = integer(artifact.pid if artifact.pid is not None else data.get("pid"))
    data["ppid"] = integer(data.get("ppid"))
    data["process_name"] = basename(
        data.get("process_name") or data.get("name") or data.get("image")
    )
    data["target_name"] = basename(data.get("target_name") or data.get("target_image"))
    data["path"] = str(data["path"]).replace("/", "\\").lower() if data.get("path") else None
    for key in (
        "process_guid",
        "source_process_guid",
        "target_process_guid",
        "parent_process_guid",
    ):
        if data.get(key):
            try:
                guid = UUID(str(data[key]))
                data[key] = str(guid) if guid.int else None
            except ValueError:
                data[key] = None
    if artifact.artifact_type in {"process", "process_tree"}:
        data.setdefault("process_creation_time", data.get("created_at"))
    if data.get("process_creation_time"):
        parsed = timestamp(data["process_creation_time"])
        if parsed:
            data["process_creation_time"] = parsed.isoformat()
        else:
            try:
                # A naive creation time can separate snapshot lifetimes but cannot order events.
                data["process_creation_time"] = datetime.fromisoformat(
                    str(data["process_creation_time"])
                ).isoformat()
            except ValueError:
                data["process_creation_time"] = None
    for key, default in (("timestamp_precision", 0.000001), ("evidence_reliability", 0.7)):
        value = data.get(key, default)
        data[key] = (
            float(value)
            if isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value >= 0
            else default
        )
    for key in ("start", "end", "start_address", "match_address", "source_pid", "target_pid"):
        if key in data:
            data[key] = integer(data[key])
    if artifact.artifact_type in {"memory_region", "module"}:
        data["private"] = boolean(data.get("private", data.get("private_memory")))
        data["executable"] = (
            boolean(data.get("executable"))
            if data.get("executable") is not None
            else executable(data.get("protection"))
        )
        data["backing"] = str(data.get("backing", "UNKNOWN")).upper()
        if data["backing"] not in {"FILE_BACKED", "ANONYMOUS", "UNBACKED", "UNKNOWN"}:
            data["backing"] = "UNKNOWN"
        if artifact.artifact_type == "memory_region":
            data.setdefault("address_space", "process_virtual")
            # Volatility VAD end addresses are inclusive. Other adapters declare their convention.
            data.setdefault("end_inclusive", True)
    if artifact.artifact_type == "thread":
        data.setdefault("address_space", "process_virtual")
    if artifact.artifact_type == "signature_match":
        data["rule_name"] = data.get("rule_name") or data.get("rule")
        data.setdefault("match_address", integer(data.get("match_location", data.get("offset"))))
        data["valid_match"] = bool(data.get("rule_name")) and data.get("valid_match") is not False
    if (
        artifact.artifact_type in {"handle", "process_handle"}
        and str(data.get("handle_type", "")).lower() == "process"
    ):
        # Volatility names may contain a PID suffix; a missing target identity remains unresolved.
        match = re.fullmatch(r"(.+?)\s+Pid\s+(\d+)", str(data.get("name", "")), re.IGNORECASE)
        if match:
            data["target_name"] = basename(match[1])
            data["target_pid"] = int(match[2])
    access = integer(data.get("granted_access", data.get("access")))
    data["can_read_memory"] = bool(access & 0x10) if access is not None else None
    data["can_write_memory"] = bool(access & 0x20) if access is not None else None
    if data.get("command_line") is not None:
        data["command_line_lower"] = str(data["command_line"]).lower()
    if artifact.artifact_type == "memory_protection_transition":
        data["old_executable"] = executable(data.get("old_protection"))
        data["new_executable"] = executable(data.get("new_protection"))
        old = data.get("old_protection")
        numeric = integer(old)
        if numeric is not None:
            data["old_writable"] = numeric & 0xFF in {4, 8, 64, 128}
        elif isinstance(old, str):
            if re.fullmatch(r"[r-][w-][x-][ps-]?", old):
                data["old_writable"] = old[1] == "w"
            elif old.startswith("PAGE_") and executable(old) is not None:
                data["old_writable"] = old in {
                    "PAGE_READWRITE",
                    "PAGE_WRITECOPY",
                    "PAGE_EXECUTE_READWRITE",
                    "PAGE_EXECUTE_WRITECOPY",
                }
        data.setdefault("address_space", "process_virtual")
        data.setdefault("end_inclusive", False)
    if data.get("path") and data.get("system_root") and data.get("process_name"):
        root = str(data["system_root"]).replace("/", "\\").rstrip("\\").lower()
        data["system_path_expected"] = data["path"] == root + "\\system32\\" + data["process_name"]
    data["timestamp_utc"] = timestamp(data.get("timestamp"))
    data["host_id"] = str(data["host_id"]).lower() if data.get("host_id") else None
    data["logon_id"] = integer(data.get("logon_id"))
    scope = (
        str(artifact.analysis_run_id),
        data.get("host_id") or "",
        str(
            data.get("acquisition_id") or data.get("acquisition_scope") or artifact.analysis_run_id
        ),
    )
    return NormalizedArtifact(artifact, data, scope)
