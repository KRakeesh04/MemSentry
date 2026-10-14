"""Workspace case operations shared by desktop pages."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from memsentry.models.case import Case, CaseCreate, CaseStatus
from memsentry.storage.database import Database
from memsentry.storage.repositories.case_repository import CaseRepository


def generate_case_number() -> str:
    """Suggest an identifier; database uniqueness still applies on creation."""
    return f"CASE-{datetime.now(UTC):%Y%m%d}-{uuid4().hex[:8].upper()}"


def workspace_database(workspace: str | Path) -> Database:
    if not str(workspace).strip():
        raise ValueError("Choose a workspace folder first.")
    folder = Path(workspace).expanduser().resolve()
    if not folder.is_dir():
        raise ValueError("Choose an existing workspace folder.")
    return Database(folder / "memsentry.sqlite3")


def create_case(workspace: str, number: str, name: str, description: str) -> Case:
    if not number.strip() or not name.strip():
        raise ValueError("Enter a case number and name.")
    database = workspace_database(workspace)
    database.initialize()
    return CaseRepository(database).create(
        CaseCreate(
            case_number=number.strip(),
            name=name.strip(),
            description=description.strip() or None,
        )
    )

def update_case_status(
    workspace: str | Path,
    case_id: UUID,
    status: CaseStatus,
) -> Case:
    database = workspace_database(workspace)
    return CaseRepository(database).change_status(case_id, status)
