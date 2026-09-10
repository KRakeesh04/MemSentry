from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class EvidenceOS(StrEnum):
    """Operating system contained within the RAM dump."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class IntegrityStatus(StrEnum):
    """Integrity status of the forensic evidence file."""

    VERIFIED = "verified"
    MODIFIED = "modified"
    UNAVAILABLE = "unavailable"


def _validate_sha256_hex(value: str) -> str:
    """Ensure SHA-256 is a valid 64-character hex string."""
    value = value.strip().lower()
    if len(value) != 64:
        raise ValueError("sha256 must be a 64-character hexadecimal string")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("sha256 must be a 64-character hexadecimal string") from exc
    return value


class EvidenceCreate(BaseModel):
    """Data required to register new forensic RAM evidence."""

    case_id: UUID
    original_filename: str
    file_path: Path
    file_size_bytes: int = Field(ge=0)
    sha256: str
    evidence_os: EvidenceOS | None = None

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        return _validate_sha256_hex(value)


class Evidence(BaseModel):
    """Forensic evidence stored in the MemSentry database."""

    id: UUID
    case_id: UUID
    original_filename: str
    file_path: Path
    file_size_bytes: int = Field(ge=0)
    sha256: str
    evidence_os: EvidenceOS | None
    integrity_status: IntegrityStatus
    registered_at: datetime

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        return _validate_sha256_hex(value)
