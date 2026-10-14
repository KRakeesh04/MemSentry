"""Windows XML and vendor-neutral EDR adapters.

Schema references: Microsoft Sysmon event descriptions; Microsoft Security event
1102/4624/4625/4672/4688 XML. Event identity includes provider AND channel.
1102 UserData is from Microsoft-Windows-Eventlog, not Security-Auditing.
EDR input: schema_version=1, artifact_type, normalized_data, optional source_record_id.
Only supplied observations are normalized; no dump content or trust is inferred.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID
from xml.etree import ElementTree

from memsentry.correlation.normalization import ARTIFACT_TYPES, basename, integer, timestamp
from memsentry.models.artifact import ArtifactCreate


class TelemetryError(ValueError):
    pass


def _time_fields(value: Any) -> dict[str, Any]:
    parsed = timestamp(value)
    text = str(value) if value is not None else None
    fraction = re.search(r"\.(\d+)", text or "")
    zone = re.search(r"(Z|[+-]\d\d:\d\d)$", text or "")
    return {
        "timestamp": parsed.isoformat() if parsed else None,
        "original_timestamp": text,
        "timestamp_source": "event_record",
        "timestamp_precision": 10 ** -len(fraction[1]) if fraction else 1,
        "timestamp_timezone": zone[0] if zone else None,
    }


def parse_windows_xml(
    xml: str,
    analysis_run_id: UUID,
    plugin_run_id: UUID,
    *,
    acquisition_id: str,
    source_file: str = "",
) -> ArtifactCreate:
    if len(xml) > 4 * 1024 * 1024 or "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise TelemetryError("Unsafe or oversized event XML")
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise TelemetryError(f"Malformed Windows event XML: {exc}") from exc

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    system = next((child for child in root if local(child.tag) == "System"), None)
    if system is None:
        raise TelemetryError("Windows event has no System metadata")
    fields = {local(child.tag): child for child in system}

    def content(name: str) -> str | None:
        element = fields.get(name)
        return element.text if element is not None else None

    provider_node, time_node = fields.get("Provider"), fields.get("TimeCreated")
    provider = provider_node.attrib.get("Name") if provider_node is not None else None
    channel, event_id = content("Channel"), integer(content("EventID"))
    values: dict[str, Any] = {}
    for child in root:
        if local(child.tag) in {"EventData", "UserData"}:
            for item in child.iter():
                if len(item) == 0:
                    values[item.attrib.get("Name", local(item.tag))] = item.text
    data: dict[str, Any] = {
        "provider": provider,
        "channel": channel,
        "event_id": event_id,
        "host_id": content("Computer"),
        "source_record_id": content("EventRecordID"),
        "source_event_id": event_id,
        "acquisition_id": acquisition_id,
        "source_tool": "windows_event_log",
        "source_file": source_file,
        "telemetry": True,
        **_time_fields(time_node.attrib.get("SystemTime") if time_node is not None else None),
    }
    kind = "windows_event"
    if provider == "Microsoft-Windows-Sysmon" and channel == "Microsoft-Windows-Sysmon/Operational":
        kind = {
            1: "process",
            8: "remote_thread",
            10: "process_access",
            11: "file_creation",
            25: "process_tampering",
        }.get(event_id or -1, "windows_event")
        cross = event_id in {8, 10}
        data.update(
            {
                "pid": integer(values.get("SourceProcessId" if cross else "ProcessId")),
                "process_guid": values.get("SourceProcessGUID" if cross else "ProcessGuid")
                or values.get("SourceProcessGuid" if cross else "ProcessGUID"),
                "process_name": basename(values.get("SourceImage" if cross else "Image")),
                "path": values.get("SourceImage" if cross else "Image"),
                "command_line": values.get("CommandLine"),
                "ppid": integer(values.get("ParentProcessId")),
                "parent_process_guid": values.get("ParentProcessGuid"),
                "parent_image": values.get("ParentImage"),
                "logon_id": values.get("LogonId"),
                "user": values.get("User"),
            }
        )
        if event_id == 1:
            data["process_creation_time"] = data["timestamp"]
        if cross:
            data.update(
                {
                    "source_process_guid": data["process_guid"],
                    "source_pid": data["pid"],
                    "target_process_guid": values.get("TargetProcessGUID")
                    or values.get("TargetProcessGuid"),
                    "target_pid": integer(values.get("TargetProcessId")),
                    "target_image": values.get("TargetImage"),
                    "target_name": basename(values.get("TargetImage")),
                    "granted_access": values.get("GrantedAccess"),
                    "start_address": values.get("StartAddress"),
                    "address_space": "process_virtual",
                    "start_module": values.get("StartModule"),
                    "start_function": values.get("StartFunction"),
                }
            )
        if event_id == 11:
            data["file_path"] = values.get("TargetFilename")
        if event_id == 25:
            data["tampering_type"] = values.get("Type")
    elif provider == "Microsoft-Windows-Security-Auditing" and channel == "Security":
        if event_id in {4624, 4625, 4672}:
            kind = "authentication_event"
            prefix = "Target" if event_id in {4624, 4625} else "Subject"
            data.update(
                {
                    "logon_id": values.get(prefix + "LogonId"),
                    "user_sid": values.get(prefix + "UserSid"),
                    "user": values.get(prefix + "UserName"),
                    "domain": values.get(prefix + "DomainName"),
                    "logon_type": integer(values.get("LogonType")),
                    "status": values.get("Status"),
                }
            )
        elif event_id == 4688:
            kind = "process"
            data.update(
                {
                    "pid": integer(values.get("NewProcessId")),
                    "ppid": integer(values.get("ProcessId")),
                    "process_name": basename(values.get("NewProcessName")),
                    "path": values.get("NewProcessName"),
                    "process_creation_time": data["timestamp"],
                    "command_line": values.get("CommandLine"),
                    "logon_id": values.get("SubjectLogonId"),
                    "user_sid": values.get("SubjectUserSid"),
                }
            )
    elif provider == "Microsoft-Windows-Eventlog" and channel == "Security" and event_id == 1102:
        data.update(
            {
                "logon_id": values.get("SubjectLogonId"),
                "user_sid": values.get("SubjectUserSid"),
                "user": values.get("SubjectUserName"),
                "domain": values.get("SubjectDomainName"),
            }
        )
    warnings = []
    if not provider or not channel or event_id is None:
        warnings.append(
            "Incomplete provider/channel/event identity; preserved as an unclassified event"
        )
    if data["timestamp"] is None:
        warnings.append(
            "Missing or timezone-naive event timestamp; temporal correlation unavailable"
        )
    return ArtifactCreate(
        analysis_run_id=analysis_run_id,
        plugin_run_id=plugin_run_id,
        artifact_type=kind,
        pid=data.get("pid"),
        original_data={"xml": xml, "normalized": data},
        provenance={
            "source_tool": "windows_event_log",
            "source_file": source_file,
            "source_record_id": data["source_record_id"],
            "acquisition_id": acquisition_id,
            "warnings": warnings,
        },
    )


def parse_edr_record(
    record: dict[str, Any],
    analysis_run_id: UUID,
    plugin_run_id: UUID,
    *,
    acquisition_id: str,
    source_file: str = "",
) -> ArtifactCreate:
    if record.get("schema_version") != 1 or record.get("artifact_type") not in ARTIFACT_TYPES:
        raise TelemetryError("EDR record requires schema_version 1 and a supported artifact_type")
    supplied = record.get("normalized_data")
    if not isinstance(supplied, dict):
        raise TelemetryError("EDR normalized_data must be a mapping")
    data = dict(supplied)
    for key in ("pid", "ppid", "source_pid", "target_pid"):
        if data.get(key) is not None:
            parsed = integer(data[key])
            if parsed is None:
                raise TelemetryError(f"Invalid EDR {key}")
            data[key] = parsed
    for key in (
        "dump_validated",
        "comparison_reliable",
        "relocations_accounted",
        "loader_changes_accounted",
        "known_benign",
        "authorized_maintenance",
        "entry_point_anomaly",
        "private",
        "executable",
        "old_writable",
    ):
        if data.get(key) is not None and not isinstance(data[key], bool):
            raise TelemetryError(f"EDR {key} must be a boolean")
    data.update(
        {
            **_time_fields(data.get("timestamp")),
            "acquisition_id": acquisition_id,
            "source_file": source_file,
            "telemetry": True,
            "source_record_id": record.get("source_record_id"),
        }
    )
    return ArtifactCreate(
        analysis_run_id=analysis_run_id,
        plugin_run_id=plugin_run_id,
        artifact_type=record["artifact_type"],
        pid=data.get("pid"),
        original_data={"source_record": record, "normalized": data},
        provenance={
            "source_tool": record.get("source_tool", "vendor_neutral_edr"),
            "source_file": source_file,
            "source_record_id": record.get("source_record_id"),
            "acquisition_id": acquisition_id,
        },
    )
