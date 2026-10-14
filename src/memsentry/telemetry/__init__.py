"""Optional telemetry enrichment; memory-only analysis has no telemetry dependency."""

from memsentry.telemetry.adapters import TelemetryError, parse_edr_record, parse_windows_xml
from memsentry.telemetry.service import TelemetryImportService

__all__ = ["TelemetryError", "TelemetryImportService", "parse_edr_record", "parse_windows_xml"]
